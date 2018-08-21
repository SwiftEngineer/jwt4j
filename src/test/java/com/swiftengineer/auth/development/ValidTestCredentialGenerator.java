package com.swiftengineer.auth.development;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author swift
 */
public class ValidTestCredentialGenerator {
    private X509Certificate testCertificate;
    private RSAPrivateKey testKey;

    public ValidTestCredentialGenerator() throws Exception {
        this.testCertificate = generateTestCertificate();
        this.testKey = generateTestKey();
    }

    /**
     * Generate a RSA key for testing purposes. This can be used to create a JwtIssuer and JwtVerifier.
     *
     * DO NOT USE FOR PRODUCTION OR STAGING INSTANCES OF YOUR APPLICATION!!! NOT SAFE!!!
     *
     * @return RSAPrivateKey for testing only!
     */
    private RSAPrivateKey generateTestKey() throws Exception {
        String keyPemEncoded =
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCssQWrgLNfWJYn\n" +
                "/ec3lweT3ASq9fPA7AgmrIK/FehxMCb1/w9zUrMMccmwg4fdG7762zZ1OOunDu+N\n" +
                "VUfE26MFNxn1C7kqL6zbScRoQd1Y0pArvp0hcx7BkCFhXrQqPuqnZ05gMfxXUs2n\n" +
                "0YlRm791FNcdalDxKZI1+1onKIuhmRMDWbM1u4X4xogM3mVCjSX7tPDYIwJtCiap\n" +
                "OGuCmFnuGqTek5OVmFUDoLphOFALtZC6nhVPyVDzwGFyQcLFGcTfvfPWbTiW9Y1y\n" +
                "QKEUSmxNIlYImXouxFWoeSfpzRvpam/9pNYXoSPbZLpz+2Zt2eLgyTHnEG9Gpou8\n" +
                "9xdSXAe9AgMBAAECggEAHtO+8l2YJ5YVv+/YPZktVhy5jJc5OyAnWFgFQv0zMDlr\n" +
                "SxCL/octxTPu0B66uyK/1eIZ95UApCLLaoxlsmOO11h9vruoAzrdfYvOjtnrHHcC\n" +
                "G3z8acM2I1GKU+pm+P+gPd/4Ir3pkOEMK0ABZlsKM2lT+UFIT7SfEBndfw4C1wbE\n" +
                "Pwu+0Cdy1+UmI+iigTYDQovSQlVWjvVHNd2Mi/QhWpR4Lgz0sMpXmbDwNhkJ0T0H\n" +
                "pp6bSXHgZnJWyfBvKScnpEUIad44b3KCfzHZnnrknu14C2jZcLaLz3kaIcKGjqLI\n" +
                "GM9UDO7FaiGyLqCfDOMc4JanViRXl3JMCdAamviEgQKBgQDYrYerMfPQSW4eloIw\n" +
                "aXMWZIJneeykf1G/8bfVc+uwczoxYIW9GoAW0GY+ykbn043feVq/dXHSUb5ngfP4\n" +
                "1UWVYirXC/pDN7m23cwcGKodJ5RIbzGT5F7tJNHseJGe63r7fTr1WpE6o2ZrLRGk\n" +
                "Q+Ts+IUClqV+M3SQ8gtFjQKHnQKBgQDMB/a1f8foHaz2zFy4+enufhMpaT/0JLxb\n" +
                "tPgeopVZypNdiH0ohdaQ3tEk2QWVmNWBVy7xdMhpByzF1L/QmRpM9OIzo1ToVmT/\n" +
                "9zO1W3WG+N6UjKw4GIx6eqldCNb/iaVYi4rV5q+fJknL452uWXANnL09Je300kuH\n" +
                "CInSXC5WoQKBgQC1BUSy4aiv+qjlJRjfGTntG0tW56WsSDIkCe1rhs0BPUMAvYL9\n" +
                "2YXpiXHiQ1u5kiSU7u3BxnyxGVnZX9hTqtnXU4w23OrX/VZKUEKVtoVolghr+3mP\n" +
                "9NrZhEldJd2Cx3iXYqg/EssCEkEeiSiT86Tt1TJKV1ErfhGEhrKkCIp0gQKBgQCK\n" +
                "ooKlUv0PoFJto/EBE3c7wVjd05FMIEYIfk/16P1YdMhrTpnUlhR0faJYykn8G0w/\n" +
                "xXC1Smf+zYxDpErtv4pabi7hbYL9F+8q6dqtyUZzftkm0OsYdr3FX2GDQMVt/yZl\n" +
                "ovOkYkpE9qxAKRp0ZHs6FJ2VVhd5Ogdt6oRTdqVZ4QKBgFwUhx9h54QsXvOJ4qHh\n" +
                "GMHi9/P4yRSfUaf+aLGMIZqyaQ8CmOj0SImXvSzaur/kDhBs+e/HrRIR8peNr2ee\n" +
                "eZ+xy6xEzivzGtUYHT+NweZLaOeeKHO+5N13WNZgBJi0yeCcDmz0dZyoLHLuyR+Z\n" +
                "va2BgkOhDT0T9HrWyPYXghgb";

        byte[] keyBytes = Base64.decodeBase64(keyPemEncoded);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) fact.generatePrivate(keySpec);
    }


    /**
     * Generate a X509Certificate for testing purposes. This can be used to create a JwtIssuer and JwtVerifier.
     *
     * DO NOT USE FOR PRODUCTION OR STAGING INSTANCES OF YOUR APPLICATION!!! NOT SAFE!!!
     *
     * @return X509Certificate for testing only!
     * @throws CertificateException
     */
    private X509Certificate generateTestCertificate() throws CertificateException {
        //        [
        //            Version: V3
        //            Subject: EMAILADDRESS=taylor@hgdata.com, CN=test-cert.hgdata.info, O=Test Cert, ST=CA, C=CA
        //
        //            Signature Algorithm: SHA256withRSA, OID = 1.2.840.113549.1.1.11
        //
        //            Key:  Sun RSA public key, 2048 bits
        //            public exponent: 65537
        //            Validity: [From: Tue Feb 07 22:04:38 PST 2017,
        //                    To: Wed Feb 07 22:04:38 PST 2018]
        //            Issuer: EMAILADDRESS=taylor@hgdata.com, CN=test-cert.hgdata.info, O=Test Cert, ST=CA, C=CA
        //            SerialNumber: [    dae7b40a 7a843561]
        //
        //            Certificate Extensions: 3
        //                    [1]: ObjectId: 2.5.29.35 Criticality=false
        //            AuthorityKeyIdentifier [
        //                    KeyIdentifier [
        //                            0000: 8B A9 84 5E E8 E4 AA BB   4A 9C D6 13 46 4C 82 2B  ...^....J...FL.+
        //                    0010: 1E FB A4 6E                                        ...n
        //        ]
        //
        //        Algorithm: [SHA256withRSA]
        //        Signature:
        //        0000: 64 60 BC 5A C6 AA 99 37   46 63 15 04 57 6F 09 5D  d`.Z...7Fc..Wo.]
        //        0010: 34 49 0D B5 7D 82 BB 27   68 A2 20 BF B3 B3 1F 7E  4I.....'h. .....
        //        0020: A1 3F 76 2E 3F A9 40 2F   A4 6A 8E EF 77 76 DE 0B  .?v.?.@/.j..wv..
        //        0030: 49 04 64 D5 16 31 DF 9F   31 28 8E B9 6D 30 8A 10  I.d..1..1(..m0..
        //        0040: 97 6F B7 2B B2 0B F4 F2   66 3A 7A 29 D4 33 68 5D  .o.+....f:z).3h]
        //        0050: 66 A0 83 12 76 BA 76 C5   E7 B5 0E EF 94 16 0F 50  f...v.v........P
        //        0060: 7C CA 46 00 4D F7 8B 79   CA 24 E8 AE 0E B2 D2 31  ..F.M..y.$.....1
        //        0070: F0 E2 B8 6D 81 46 B7 1C   6F 0F 9C A8 70 08 CD 95  ...m.F..o...p...
        //        0080: 67 95 2D 19 91 9F 24 32   01 0E 74 62 59 3E E7 29  g.-...$2..tbY>.)
        //        0090: 66 CE FD B6 8B 8B 83 A5   BC E2 C8 D5 B5 3C 81 39  f............<.9
        //        00A0: 13 E6 FE 20 3E 4D 45 B5   61 6C 2A 9E 15 C9 74 09  ... >ME.al*...t.
        //        00B0: 89 22 40 84 3F FB 78 5D   76 5D 22 A1 E6 BC CB 54  ."@.?.x]v]"....T
        //        00C0: 89 BE 0F 62 CD CD BB 9B   4B 47 2C B8 0C E0 75 F4  ...b....KG,...u.
        //        00D0: BD 29 2F 70 DD EC 61 8A   76 81 2F E3 F2 74 31 34  .)/p..a.v./..t14
        //        00E0: AD B5 1A 9F 85 74 4D DF   F3 E9 99 1B 88 92 9B 92  .....tM.........
        //        00F0: 23 B9 89 9D 43 18 43 E1   AC 8F 15 30 83 BC 4B AB  #...C.C....0..K.

        String rawPemEncodedCert = "MIIEOTCCAyGgAwIBAgIJANrntAp6hDVhMA0GCSqGSIb3DQEBCwUAMHAxCzAJBgNV\n" +
                "BAYTAkNBMQswCQYDVQQIEwJDQTESMBAGA1UEChMJVGVzdCBDZXJ0MR4wHAYDVQQD\n" +
                "ExV0ZXN0LWNlcnQuaGdkYXRhLmluZm8xIDAeBgkqhkiG9w0BCQEWEXRheWxvckBo\n" +
                "Z2RhdGEuY29tMB4XDTE3MDIwODA2MDQzOFoXDTE4MDIwODA2MDQzOFowcDELMAkG\n" +
                "A1UEBhMCQ0ExCzAJBgNVBAgTAkNBMRIwEAYDVQQKEwlUZXN0IENlcnQxHjAcBgNV\n" +
                "BAMTFXRlc3QtY2VydC5oZ2RhdGEuaW5mbzEgMB4GCSqGSIb3DQEJARYRdGF5bG9y\n" +
                "QGhnZGF0YS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCssQWr\n" +
                "gLNfWJYn/ec3lweT3ASq9fPA7AgmrIK/FehxMCb1/w9zUrMMccmwg4fdG7762zZ1\n" +
                "OOunDu+NVUfE26MFNxn1C7kqL6zbScRoQd1Y0pArvp0hcx7BkCFhXrQqPuqnZ05g\n" +
                "MfxXUs2n0YlRm791FNcdalDxKZI1+1onKIuhmRMDWbM1u4X4xogM3mVCjSX7tPDY\n" +
                "IwJtCiapOGuCmFnuGqTek5OVmFUDoLphOFALtZC6nhVPyVDzwGFyQcLFGcTfvfPW\n" +
                "bTiW9Y1yQKEUSmxNIlYImXouxFWoeSfpzRvpam/9pNYXoSPbZLpz+2Zt2eLgyTHn\n" +
                "EG9Gpou89xdSXAe9AgMBAAGjgdUwgdIwHQYDVR0OBBYEFIuphF7o5Kq7SpzWE0ZM\n" +
                "gise+6RuMIGiBgNVHSMEgZowgZeAFIuphF7o5Kq7SpzWE0ZMgise+6RuoXSkcjBw\n" +
                "MQswCQYDVQQGEwJDQTELMAkGA1UECBMCQ0ExEjAQBgNVBAoTCVRlc3QgQ2VydDEe\n" +
                "MBwGA1UEAxMVdGVzdC1jZXJ0LmhnZGF0YS5pbmZvMSAwHgYJKoZIhvcNAQkBFhF0\n" +
                "YXlsb3JAaGdkYXRhLmNvbYIJANrntAp6hDVhMAwGA1UdEwQFMAMBAf8wDQYJKoZI\n" +
                "hvcNAQELBQADggEBAGRgvFrGqpk3RmMVBFdvCV00SQ21fYK7J2iiIL+zsx9+oT92\n" +
                "Lj+pQC+kao7vd3beC0kEZNUWMd+fMSiOuW0wihCXb7crsgv08mY6einUM2hdZqCD\n" +
                "Ena6dsXntQ7vlBYPUHzKRgBN94t5yiTorg6y0jHw4rhtgUa3HG8PnKhwCM2VZ5Ut\n" +
                "GZGfJDIBDnRiWT7nKWbO/baLi4OlvOLI1bU8gTkT5v4gPk1FtWFsKp4VyXQJiSJA\n" +
                "hD/7eF12XSKh5rzLVIm+D2LNzbubS0csuAzgdfS9KS9w3exhinaBL+PydDE0rbUa\n" +
                "n4V0Td/z6ZkbiJKbkiO5iZ1DGEPhrI8VMIO8S6s=";
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decodeBase64(rawPemEncodedCert)));
    }

    public X509Certificate getTestCertificate() {
        return testCertificate;
    }

    public RSAPrivateKey getTestKey() {
        return testKey;
    }
}
