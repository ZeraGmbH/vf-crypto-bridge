#ifndef VEINCRYPTO_OPENSSLSIGNATUREHANDLERR_H
#define VEINCRYPTO_OPENSSLSIGNATUREHANDLERR_H

#include "vfcryptobridge_export.h"
#include <QByteArray>

namespace VeinCryptoBridge
{
  class VFCRYPTOBRIDGE_EXPORT OpenSSLSignatureHandler
  {

  public:
    OpenSSLSignatureHandler();
    ~OpenSSLSignatureHandler();

    /**
     * @brief createCMSSignature
     * @param t_caCertData certificate data
     * @param t_privKeyData private key data
     * @param t_payloadData data to be signed
     * @param t_privKeyPassword mandatory password of the private key
     * @param out_signingSuccess success indicator
     * @return data with signature header/footer or QByteArray() on failure
     */
    QByteArray createCMSSignature(QByteArray t_caCertData, QByteArray t_privKeyData, QByteArray t_payloadData, QByteArray t_privKeyPassword, bool *out_signingSuccess=nullptr);

    /**
     * @brief verifyCMSSignature
     * @param t_caCertData certificate data
     * @param t_signedData signed data
     * @param out_verificationSuccess success indicator
     * @return data stripped by the signature header/footer or QByteArray() on failure
     */
    QByteArray verifyCMSSignature(QByteArray t_caCertData, QByteArray t_signedData, bool *out_verificationSuccess=nullptr);
  };
} // namespace VeinCrypto
#endif // VEINCRYPTO_OPENSSLSIGNATUREHANDLERR_H
