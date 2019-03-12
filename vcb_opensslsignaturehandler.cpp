/*
 * Copyright 2008-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2018 Zera GmbH
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file COPYING.SSL-SSLeay in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "vcb_opensslsignaturehandler.h"

#include <QDebug>

#include <functional>

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

namespace VeinCryptoBridge
{
  static std::function<int(char*,int,int,void*)> s_pwCallbackImpl;

  //cannot pass capturing lambda as function pointer directly so do it this way
  int pwCallback(char *out_buf, int t_size, int t_rwFlag, void *t_userData) {
    return s_pwCallbackImpl(out_buf, t_size, t_rwFlag, t_userData);
  }

  OpenSSLSignatureHandler::OpenSSLSignatureHandler()
  {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
  }

  OpenSSLSignatureHandler::~OpenSSLSignatureHandler()
  {
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
  }

  QByteArray OpenSSLSignatureHandler::createCMSSignature(QByteArray t_caCertData, QByteArray t_privKeyData, QByteArray t_payloadData, QByteArray t_privKeyPassword, bool *out_signingSuccess)
  {
    //never use unencrypted private keys!!
    Q_ASSERT(t_privKeyPassword.isEmpty() == false);

    QByteArray retVal;
    bool successFlag = false;

    BIO *inBIO = nullptr, *outBIO = nullptr, *certBIO = nullptr, *privKeyBIO = nullptr;
    X509 *caCert = nullptr;
    EVP_PKEY *privKey = nullptr;
    CMS_ContentInfo *cmsInfo = nullptr;

    /*
     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
     * non-detached set CMS_STREAM
     */
    int flags = CMS_DETACHED | CMS_STREAM;



    // Read in signer certificate and private key
    certBIO = BIO_new_mem_buf(t_caCertData.data(), t_caCertData.size());
    privKeyBIO = BIO_new_mem_buf(t_privKeyData.data(), t_privKeyData.size());

    if(certBIO && privKeyBIO)
    {
      caCert = PEM_read_bio_X509(certBIO, nullptr, 0, nullptr);

      //need to overwrite this every time the funciton is called since the captured value changes!
      s_pwCallbackImpl = [t_privKeyPassword](char *t_buf, int t_size, int t_rwflag, void *t_userdata) {
        Q_UNUSED(t_userdata);
        Q_ASSERT(t_rwflag == 0);
        int dataSize = t_privKeyPassword.size();
        if(dataSize>t_size) //buffer size restriction
        {
          dataSize = t_size;
        }

        memcpy(t_buf, t_privKeyPassword.data(), dataSize);

        return dataSize;
      };
      //capturing lambdas cannot be used as raw function pointers, so use an intermediate function that calls the static std::function that holds the lambda set previously
      privKey = PEM_read_bio_PrivateKey(privKeyBIO, nullptr, &pwCallback, nullptr);
      //unset callback
      s_pwCallbackImpl = nullptr;

      if(caCert && privKey)
      {
        // Open content being signed
        inBIO = BIO_new_mem_buf(t_payloadData.data(), t_payloadData.size());

        if(inBIO)
        {
          // Sign content
          cmsInfo = CMS_sign(caCert, privKey, nullptr, inBIO, flags);

          if(cmsInfo)
          {
            //in memory data
            outBIO = BIO_new(BIO_s_mem());
            if(outBIO)
            {

              if(!(flags & CMS_STREAM))
                BIO_reset(inBIO);

              // Write out S/MIME message
              if(SMIME_write_CMS(outBIO, cmsInfo, inBIO, flags))
              {
                char *outData=nullptr;
                qint64 outSize=0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast" //it's C code, they don't have static_cast
                //sets outData to point to the outBIO data
                outSize = BIO_get_mem_data(outBIO, &outData);
#pragma GCC diagnostic pop

                retVal = QByteArray(outData, outSize);
                successFlag = true;
              }
            }
          }
        }
      }
    }

    if(successFlag == false)
    {
      qWarning()<<"Error Signing Data";
      ERR_print_errors_fp(stderr);
    }

    if(cmsInfo)
      CMS_ContentInfo_free(cmsInfo);
    if(caCert)
      X509_free(caCert);
    if(privKey)
      EVP_PKEY_free(privKey);
    if(inBIO)
      BIO_free(inBIO);
    if(outBIO)
      BIO_free(outBIO);
    if(certBIO)
      BIO_free(certBIO);
    if(privKeyBIO)
      BIO_free(privKeyBIO);

    if(out_signingSuccess)
    {
      *out_signingSuccess = successFlag;
    }

    return retVal;
  }

  QByteArray OpenSSLSignatureHandler::verifyCMSSignature(QByteArray t_caCertData, QByteArray t_signedData, bool *out_verificationSuccess)
  {
    QByteArray retVal;
    bool successFlag = false;

    BIO *inBIO = nullptr, *outBIO = nullptr, *certBIO = nullptr, *contentBIO = nullptr;
    X509_STORE *certStore = nullptr;
    X509 *caCert = nullptr;
    CMS_ContentInfo *cmsInfo = nullptr;

    //set up CA certificate store
    certStore = X509_STORE_new();

    certBIO = BIO_new_mem_buf(t_caCertData.data(), t_caCertData.size());

    if(certBIO)
    {
      caCert = PEM_read_bio_X509(certBIO, nullptr, 0, nullptr);

      if(caCert)
      {
        if(X509_STORE_add_cert(certStore, caCert))
        {
          inBIO = BIO_new_mem_buf(t_signedData.data(), t_signedData.size());

          if(inBIO)
          {
            //parse signature, also reads content into contentBIO
            cmsInfo = SMIME_read_CMS(inBIO, &contentBIO);

            if(cmsInfo)
            {
              //verified content stored in memory
              outBIO = BIO_new(BIO_s_mem());

              if(outBIO)
              {
                if(CMS_verify(cmsInfo, nullptr, certStore, contentBIO, outBIO, 0))
                {
                  char *outData=nullptr;
                  qint64 outSize=0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast" //it's C code, they don't have static_cast
                  //sets outData to point to the outBIO data
                  outSize = BIO_get_mem_data(outBIO, &outData);
#pragma GCC diagnostic pop

                  retVal = QByteArray(outData, outSize);
                  successFlag = true;
                }
                else
                {
                  qWarning()<<"Verification Failure";
                  ERR_print_errors_fp(stderr);
                }
              }
            }
          }
        }
      }
    }

    if(cmsInfo)
      CMS_ContentInfo_free(cmsInfo);
    if(caCert)
      X509_free(caCert);
    if(certStore)
      X509_STORE_free(certStore);
    if(inBIO)
      BIO_free(inBIO);
    if(outBIO)
      BIO_free(outBIO);
    if(certBIO)
      BIO_free(certBIO);
    if(contentBIO)
      BIO_free(contentBIO);

    if(out_verificationSuccess)
    {
      *out_verificationSuccess = successFlag;
    }

    return retVal;
  }
} // namespace VeinCrypto
