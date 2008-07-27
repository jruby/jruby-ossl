/***** BEGIN LICENSE BLOCK *****
 * Version: CPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Common Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/cpl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2008 Ola Bini <ola.bini@gmail.com>
 * 
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the CPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the CPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl.impl;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.DERObjectIdentifier;

/**
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class ASN1Registry {
    @SuppressWarnings("unchecked")
    private static Map<String, DERObjectIdentifier> SYM_TO_OID = (Map<String, DERObjectIdentifier>)(new HashMap(org.bouncycastle.asn1.x509.X509Name.DefaultLookUp));
    @SuppressWarnings("unchecked")
    private static Map<DERObjectIdentifier, String> OID_TO_SYM = (Map<DERObjectIdentifier, String>)(new HashMap(org.bouncycastle.asn1.x509.X509Name.DefaultSymbols));
    private static Map<DERObjectIdentifier, Integer> OID_TO_NID = new HashMap<DERObjectIdentifier, Integer>();
    private static Map<Integer, DERObjectIdentifier> NID_TO_OID = new HashMap<Integer, DERObjectIdentifier>();
    private static Map<Integer, String> NID_TO_SN = new HashMap<Integer, String>();
    private static Map<Integer, String> NID_TO_LN = new HashMap<Integer, String>();
    
    static Integer obj2nid(String oid) {
        return obj2nid(new DERObjectIdentifier(oid));
    }

    static String ln2oid(String ln) {
        return SYM_TO_OID.get(ln).getId();
    }

    static Integer obj2nid(DERObjectIdentifier oid) {
        return OID_TO_NID.get(oid);
    }

    static String o2a(DERObjectIdentifier obj) {
        Integer nid = obj2nid(obj);
        String one = NID_TO_LN.get(nid);
        if(one == null) {
            one = NID_TO_SN.get(nid);
        }
        return one;
    }

    static String nid2ln(int nid) {
        return nid2ln(Integer.valueOf(nid));
    }

    static String nid2ln(Integer nid) {
        return NID_TO_LN.get(nid);
    }

    static void addObject(int nid, String sn, String ln, String oid) {
        if(null != oid && (null != sn || null != ln)) {
            DERObjectIdentifier ident = new DERObjectIdentifier(oid);
            if(sn != null) {
                SYM_TO_OID.put(sn.toLowerCase(),ident);
            }
            if(ln != null) {
                SYM_TO_OID.put(ln.toLowerCase(),ident);
            }
            OID_TO_SYM.put(ident,sn == null ? ln : sn);
            OID_TO_NID.put(ident,nid);
            NID_TO_OID.put(nid,ident);
            NID_TO_SN.put(nid,sn);
            NID_TO_LN.put(nid,ln);
        }        
    }

    static {
        addObject(0, null, null,"1.2.840.113549.1.12.1");
        addObject(1, null, "rsadsi","1.2.840.113549");
        addObject(2, null, "pkcs","1.2.840.113549.1");
        addObject(3, "MD2", "md2","1.2.840.113549.2.2");
        addObject(4, "MD5", "md5","1.2.840.113549.2.5");
        addObject(5, "RC4", "rc4","1.2.840.113549.3.4");
        addObject(6, null, "rsaEncryption","1.2.840.113549.1.1.1");
        addObject(7, "RSA-MD2", "md2WithRSAEncryption","1.2.840.113549.1.1.2");
        addObject(8, "RSA-MD5", "md5WithRSAEncryption","1.2.840.113549.1.1.4");
        addObject(9, "PBE-MD2-DES", "pbeWithMD2AndDES-CBC","1.2.840.113549.1.5.1");
        addObject(10, "PBE-MD5-DES", "pbeWithMD5AndDES-CBC","1.2.840.113549.1.5.3");
        addObject(11, null, "X500","2.5");
        addObject(12, null, "X509","2.5.4");
        addObject(13, "CN", "commonName","2.5.4.3");
        addObject(14, "C", "countryName","2.5.4.6");
        addObject(15, "L", "localityName","2.5.4.7");
        addObject(16, "ST", "stateOrProvinceName","2.5.4.8");
        addObject(17, "O", "organizationName","2.5.4.10");
        addObject(18, "OU", "organizationalUnitName","2.5.4.11");
        addObject(19, "RSA", "rsa","2.5.8.1.1");
        addObject(20, null, "pkcs7","1.2.840.113549.1.7");
        addObject(PKCS7.NID_pkcs7_data, null, "pkcs7-data","1.2.840.113549.1.7.1");
        addObject(PKCS7.NID_pkcs7_signed, null, "pkcs7-signedData","1.2.840.113549.1.7.2");
        addObject(PKCS7.NID_pkcs7_enveloped, null, "pkcs7-envelopedData","1.2.840.113549.1.7.3");
        addObject(PKCS7.NID_pkcs7_signedAndEnveloped, null, "pkcs7-signedAndEnvelopedData","1.2.840.113549.1.7.4");
        addObject(PKCS7.NID_pkcs7_digest, null, "pkcs7-digestData","1.2.840.113549.1.7.5");
        addObject(PKCS7.NID_pkcs7_encrypted, null, "pkcs7-encryptedData","1.2.840.113549.1.7.6");
        addObject(27, null, "pkcs3","1.2.840.113549.1.3");
        addObject(28, null, "dhKeyAgreement","1.2.840.113549.1.3.1");
        addObject(29, "DES-ECB", "des-ecb","1.3.14.3.2.6");
        addObject(30, "DES-CFB", "des-cfb","1.3.14.3.2.9");
        addObject(31, "DES-CBC", "des-cbc","1.3.14.3.2.7");
        addObject(32, "DES-EDE", "des-ede","1.3.14.3.2.17");
        addObject(33, "DES-EDE3", "des-ede3",null);
        addObject(34, "IDEA-CBC", "idea-cbc","1.3.6.1.4.1.188.7.1.1.2");
        addObject(35, "IDEA-CFB", "idea-cfb",null);
        addObject(36, "IDEA-ECB", "idea-ecb",null);
        addObject(37, "RC2-CBC", "rc2-cbc","1.2.840.113549.3.2");
        addObject(38, "RC2-ECB", "rc2-ecb",null);
        addObject(39, "RC2-CFB", "rc2-cfb",null);
        addObject(40, "RC2-OFB", "rc2-ofb",null);
        addObject(41, "SHA", "sha","1.3.14.3.2.18");
        addObject(42, "RSA-SHA", "shaWithRSAEncryption","1.3.14.3.2.15");
        addObject(43, "DES-EDE-CBC", "des-ede-cbc",null);
        addObject(44, "DES-EDE3-CBC", "des-ede3-cbc","1.2.840.113549.3.7");
        addObject(45, "DES-OFB", "des-ofb","1.3.14.3.2.8");
        addObject(46, "IDEA-OFB", "idea-ofb",null);
        addObject(47, null, "pkcs9","1.2.840.113549.1.9");
        addObject(48, "Email", "emailAddress","1.2.840.113549.1.9.1");
        addObject(49, null, "unstructuredName","1.2.840.113549.1.9.2");
        addObject(50, null, "contentType","1.2.840.113549.1.9.3");
        addObject(51, null, "messageDigest","1.2.840.113549.1.9.4");
        addObject(52, null, "signingTime","1.2.840.113549.1.9.5");
        addObject(53, null, "countersignature","1.2.840.113549.1.9.6");
        addObject(54, null, "challengePassword","1.2.840.113549.1.9.7");
        addObject(55, null, "unstructuredAddress","1.2.840.113549.1.9.8");
        addObject(56, null, "extendedCertificateAttributes","1.2.840.113549.1.9.9");
        addObject(57, "Netscape", "Netscape Communications Corp.","2.16.840.1.113730");
        addObject(58, "nsCertExt", "Netscape Certificate Extension","2.16.840.1.113730.1");
        addObject(59, "nsDataType", "Netscape Data Type","2.16.840.1.113730.2");
        addObject(60, "DES-EDE-CFB", "des-ede-cfb",null);
        addObject(61, "DES-EDE3-CFB", "des-ede3-cfb",null);
        addObject(62, "DES-EDE-OFB", "des-ede-ofb",null);
        addObject(63, "DES-EDE3-OFB", "des-ede3-ofb",null);
        addObject(64, "SHA1", "sha1","1.3.14.3.2.26");
        addObject(65, "RSA-SHA1", "sha1WithRSAEncryption","1.2.840.113549.1.1.5");
        addObject(66, "DSA-SHA", "dsaWithSHA","1.3.14.3.2.13");
        addObject(67, "DSA-old", "dsaEncryption-old","1.3.14.3.2.12");
        addObject(68, "PBE-SHA1-RC2-64", "pbeWithSHA1AndRC2-CBC","1.2.840.113549.1.5.11");
        addObject(69, null, "PBKDF2","1.2.840.113549.1.5.12");
        addObject(70, "DSA-SHA1-old", "dsaWithSHA1-old","1.3.14.3.2.27");
        addObject(71, "nsCertType", "Netscape Cert Type","2.16.840.1.113730.1.1");
        addObject(72, "nsBaseUrl", "Netscape Base Url","2.16.840.1.113730.1.2");
        addObject(73, "nsRevocationUrl", "Netscape Revocation Url","2.16.840.1.113730.1.3");
        addObject(74, "nsCaRevocationUrl", "Netscape CA Revocation Url","2.16.840.1.113730.1.4");
        addObject(75, "nsRenewalUrl", "Netscape Renewal Url","2.16.840.1.113730.1.7");
        addObject(76, "nsCaPolicyUrl", "Netscape CA Policy Url","2.16.840.1.113730.1.8");
        addObject(77, "nsSslServerName", "Netscape SSL Server Name","2.16.840.1.113730.1.12");
        addObject(78, "nsComment", "Netscape Comment","2.16.840.1.113730.1.13");
        addObject(79, "nsCertSequence", "Netscape Certificate Sequence","2.16.840.1.113730.2.5");
        addObject(80, "DESX-CBC", "desx-cbc",null);
        addObject(81, "id-ce", null,"2.5.29");
        addObject(82, "subjectKeyIdentifier", "X509v3 Subject Key Identifier","2.5.29.14");
        addObject(83, "keyUsage", "X509v3 Key Usage","2.5.29.15");
        addObject(84, "privateKeyUsagePeriod", "X509v3 Private Key Usage Period","2.5.29.16");
        addObject(85, "subjectAltName", "X509v3 Subject Alternative Name","2.5.29.17");
        addObject(86, "issuerAltName", "X509v3 Issuer Alternative Name","2.5.29.18");
        addObject(87, "basicConstraints", "X509v3 Basic Constraints","2.5.29.19");
        addObject(88, "crlNumber", "X509v3 CRL Number","2.5.29.20");
        addObject(89, "certificatePolicies", "X509v3 Certificate Policies","2.5.29.32");
        addObject(90, "authorityKeyIdentifier", "X509v3 Authority Key Identifier","2.5.29.35");
        addObject(91, "BF-CBC", "bf-cbc","1.3.6.1.4.1.3029.1.2");
        addObject(92, "BF-ECB", "bf-ecb",null);
        addObject(93, "BF-CFB", "bf-cfb",null);
        addObject(94, "BF-OFB", "bf-ofb",null);
        addObject(95, "MDC2", "mdc2","2.5.8.3.101");
        addObject(96, "RSA-MDC2", "mdc2withRSA","2.5.8.3.100");
        addObject(97, "RC4-40", "rc4-40",null);
        addObject(98, "RC2-40-CBC", "rc2-40-cbc",null);
        addObject(99, "G", "givenName","2.5.4.42");
        addObject(100, "S", "surname","2.5.4.4");
        addObject(101, "I", "initials","2.5.4.43");
        addObject(102, "UID", "uniqueIdentifier","2.5.4.45");
        addObject(103, "crlDistributionPoints", "X509v3 CRL Distribution Points","2.5.29.31");
        addObject(104, "RSA-NP-MD5", "md5WithRSA","1.3.14.3.2.3");
        addObject(105, "SN", "serialNumber","2.5.4.5");
        addObject(106, "T", "title","2.5.4.12");
        addObject(107, "D", "description","2.5.4.13");
        addObject(108, "CAST5-CBC", "cast5-cbc","1.2.840.113533.7.66.10");
        addObject(109, "CAST5-ECB", "cast5-ecb",null);
        addObject(110, "CAST5-CFB", "cast5-cfb",null);
        addObject(111, "CAST5-OFB", "cast5-ofb",null);
        addObject(112, null, "pbeWithMD5AndCast5CBC","1.2.840.113533.7.66.12");
        addObject(113, "DSA-SHA1", "dsaWithSHA1","1.2.840.10040.4.3");
        addObject(114, "MD5-SHA1", "md5-sha1",null);
        addObject(115, "RSA-SHA1-2", "sha1WithRSA","1.3.14.3.2.29");
        addObject(116, "DSA", "dsaEncryption","1.2.840.10040.4.1");
        addObject(117, "RIPEMD160", "ripemd160","1.3.36.3.2.1");
        addObject(118, "RSA-RIPEMD160", "ripemd160WithRSA","1.3.36.3.3.1.2");
        addObject(119, "RC5-CBC", "rc5-cbc","1.2.840.113549.3.8");
        addObject(120, "RC5-ECB", "rc5-ecb",null);
        addObject(121, "RC5-CFB", "rc5-cfb",null);
        addObject(122, "RC5-OFB", "rc5-ofb",null);
        addObject(123, "RLE", "run length compression","1.1.1.1.666.1");
        addObject(124, "ZLIB", "zlib compression","1.1.1.1.666.2");
        addObject(125, "extendedKeyUsage", "X509v3 Extended Key Usage","2.5.29.37");
        addObject(126, "PKIX", null,"1.3.6.1.5.5.7");
        addObject(127, "id-kp", null,"1.3.6.1.5.5.7.3");
        addObject(128, "serverAuth", "TLS Web Server Authentication","1.3.6.1.5.5.7.3.1");
        addObject(129, "clientAuth", "TLS Web Client Authentication","1.3.6.1.5.5.7.3.2");
        addObject(130, "codeSigning", "Code Signing","1.3.6.1.5.5.7.3.3");
        addObject(131, "emailProtection", "E-mail Protection","1.3.6.1.5.5.7.3.4");
        addObject(132, "timeStamping", "Time Stamping","1.3.6.1.5.5.7.3.8");
        addObject(133, "msCodeInd", "Microsoft Individual Code Signing","1.3.6.1.4.1.311.2.1.21");
        addObject(134, "msCodeCom", "Microsoft Commercial Code Signing","1.3.6.1.4.1.311.2.1.22");
        addObject(135, "msCTLSign", "Microsoft Trust List Signing","1.3.6.1.4.1.311.10.3.1");
        addObject(136, "msSGC", "Microsoft Server Gated Crypto","1.3.6.1.4.1.311.10.3.3");
        addObject(137, "msEFS", "Microsoft Encrypted File System","1.3.6.1.4.1.311.10.3.4");
        addObject(138, "nsSGC", "Netscape Server Gated Crypto","2.16.840.1.113730.4.1");
        addObject(139, "deltaCRL", "X509v3 Delta CRL Indicator","2.5.29.27");
        addObject(140, "CRLReason", "CRL Reason Code","2.5.29.21");
        addObject(141, "invalidityDate", "Invalidity Date","2.5.29.24");
        addObject(142, "SXNetID", "Strong Extranet ID","1.3.101.1.4.1");
        addObject(143, "PBE-SHA1-RC4-128", "pbeWithSHA1And128BitRC4","1.2.840.113549.1.12.1.1");
        addObject(144, "PBE-SHA1-RC4-40", "pbeWithSHA1And40BitRC4","1.2.840.113549.1.12.1.2");
        addObject(145, "PBE-SHA1-3DES", "pbeWithSHA1And3-KeyTripleDES-CBC","1.2.840.113549.1.12.1.3");
        addObject(146, "PBE-SHA1-2DES", "pbeWithSHA1And2-KeyTripleDES-CBC","1.2.840.113549.1.12.1.4");
        addObject(147, "PBE-SHA1-RC2-128", "pbeWithSHA1And128BitRC2-CBC","1.2.840.113549.1.12.1.5");
        addObject(148, "PBE-SHA1-RC2-40", "pbeWithSHA1And40BitRC2-CBC","1.2.840.113549.1.12.1.6");
        addObject(149, null, "keyBag","1.2.840.113549.1.12.10.1.1");
        addObject(150, null, "pkcs8ShroudedKeyBag","1.2.840.113549.1.12.10.1.2");
        addObject(151, null, "certBag","1.2.840.113549.1.12.10.1.3");
        addObject(152, null, "crlBag","1.2.840.113549.1.12.10.1.4");
        addObject(153, null, "secretBag","1.2.840.113549.1.12.10.1.5");
        addObject(154, null, "safeContentsBag","1.2.840.113549.1.12.10.1.6");
        addObject(155, null, "PBES2","1.2.840.113549.1.5.13");
        addObject(156, null, "PBMAC1","1.2.840.113549.1.5.14");
        addObject(157, null, "hmacWithSHA1","1.2.840.113549.2.7");
        addObject(158, "id-qt-cps", "Policy Qualifier CPS","1.3.6.1.5.5.7.2.1");
        addObject(159, "id-qt-unotice", "Policy Qualifier User Notice","1.3.6.1.5.5.7.2.2");
        addObject(160, "RC2-64-CBC", "rc2-64-cbc",null);
        addObject(161, "SMIME-CAPS", "S/MIME Capabilities","1.2.840.113549.1.9.15");
        addObject(162, "PBE-MD2-RC2-64", "pbeWithMD2AndRC2-CBC","1.2.840.113549.1.5.4");
        addObject(163, "PBE-MD5-RC2-64", "pbeWithMD5AndRC2-CBC","1.2.840.113549.1.5.6");
        addObject(164, "PBE-SHA1-DES", "pbeWithSHA1AndDES-CBC","1.2.840.113549.1.5.10");
        addObject(165, "msExtReq", "Microsoft Extension Request","1.3.6.1.4.1.311.2.1.14");
        addObject(166, "extReq", "Extension Request","1.2.840.113549.1.9.14");
        addObject(167, "name", "name","2.5.4.41");
        addObject(168, "dnQualifier", "dnQualifier","2.5.4.46");
        addObject(169, "id-pe", null,"1.3.6.1.5.5.7.1");
        addObject(170, "id-ad", null,"1.3.6.1.5.5.7.48");
        addObject(171, "authorityInfoAccess", "Authority Information Access","1.3.6.1.5.5.7.1.1");
        addObject(172, "OCSP", "OCSP","1.3.6.1.5.5.7.48.1");
        addObject(173, "caIssuers", "CA Issuers","1.3.6.1.5.5.7.48.2");
        addObject(174, "OCSPSigning", "OCSP Signing","1.3.6.1.5.5.7.3.9");
        addObject(175, "AES-128-EBC", "aes-128-ebc","2.16.840.1.101.3.4.1.1");
        addObject(176, "AES-128-CBC", "aes-128-cbc","2.16.840.1.101.3.4.1.2");
        addObject(177, "AES-128-OFB", "aes-128-ofb","2.16.840.1.101.3.4.1.3");
        addObject(178, "AES-128-CFB", "aes-128-cfb","2.16.840.1.101.3.4.1.4");
        addObject(179, "AES-192-EBC", "aes-192-ebc","2.16.840.1.101.3.4.1.21");
        addObject(180, "AES-192-CBC", "aes-192-cbc","2.16.840.1.101.3.4.1.22");
        addObject(181, "AES-192-OFB", "aes-192-ofb","2.16.840.1.101.3.4.1.23");
        addObject(182, "AES-192-CFB", "aes-192-cfb","2.16.840.1.101.3.4.1.24");
        addObject(183, "AES-256-EBC", "aes-256-ebc","2.16.840.1.101.3.4.1.41");
        addObject(184, "AES-256-CBC", "aes-256-cbc","2.16.840.1.101.3.4.1.42");
        addObject(185, "AES-256-OFB", "aes-256-ofb","2.16.840.1.101.3.4.1.43");
        addObject(186, "AES-256-CFB", "aes-256-cfb","2.16.840.1.101.3.4.1.44");
    }
}// ASN1Registry
