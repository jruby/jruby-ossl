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
 * Copyright (C) 2006, 2007 Ola Bini <ola@ologix.com>
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
package org.jruby.ext.openssl;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyClass;
import org.jruby.RubyFile;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.impl.ASN1Registry;
import org.jruby.ext.openssl.impl.BIO;
import org.jruby.ext.openssl.impl.MemBIO;
import org.jruby.ext.openssl.impl.Mime;
import org.jruby.ext.openssl.impl.NotVerifiedPKCS7Exception;
import org.jruby.ext.openssl.impl.PKCS7Exception;
import org.jruby.ext.openssl.impl.RecipInfo;
import org.jruby.ext.openssl.impl.SMIME;
import org.jruby.ext.openssl.impl.SignerInfoWithPkey;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.ext.openssl.x509store.Store;
import org.jruby.ext.openssl.x509store.StoreContext;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class PKCS7 extends RubyObject {    
    private static ObjectAllocator PKCS7_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new PKCS7(runtime, klass);
        }
    };

    public static void createPKCS7(Ruby runtime, RubyModule mOSSL) {
        RubyModule mPKCS7 = mOSSL.defineModuleUnder("PKCS7");
        RubyClass openSSLError = runtime.getModule("OpenSSL").getClass("OpenSSLError");
        mPKCS7.defineClassUnder("PKCS7Error",openSSLError,openSSLError.getAllocator());
        RubyClass cPKCS7 = mPKCS7.defineClassUnder("PKCS7",runtime.getObject(),PKCS7_ALLOCATOR);

        cPKCS7.attr_accessor(runtime.getCurrentContext(), new IRubyObject[]{runtime.newSymbol("data"),runtime.newSymbol("error_string")});

        mPKCS7.defineAnnotatedMethods(ModuleMethods.class);
        cPKCS7.defineAnnotatedMethods(PKCS7.class);

        SignerInfo.createSignerInfo(runtime,mPKCS7);
        RecipientInfo.createRecipientInfo(runtime,mPKCS7);

        mPKCS7.setConstant("TEXT",runtime.newFixnum(1));
        mPKCS7.setConstant("NOCERTS",runtime.newFixnum(2));
        mPKCS7.setConstant("NOSIGS",runtime.newFixnum(4));
        mPKCS7.setConstant("NOCHAIN",runtime.newFixnum(8));
        mPKCS7.setConstant("NOINTERN",runtime.newFixnum(16));
        mPKCS7.setConstant("NOVERIFY",runtime.newFixnum(32));
        mPKCS7.setConstant("DETACHED",runtime.newFixnum(64));
        mPKCS7.setConstant("BINARY",runtime.newFixnum(128));
        mPKCS7.setConstant("NOATTR",runtime.newFixnum(256));
        mPKCS7.setConstant("NOSMIMECAP",runtime.newFixnum(512));
    }

    public static BIO obj2bio(IRubyObject obj) {
        if(obj instanceof RubyFile) {
            throw new IllegalArgumentException("TODO: handle RubyFile correctly");
//     if (TYPE(obj) == T_FILE) {
//         OpenFile *fptr;
//         GetOpenFile(obj, fptr);
//         rb_io_check_readable(fptr);
//         bio = BIO_new_fp(fptr->f, BIO_NOCLOSE);
        } else {
            RubyString str = obj.convertToString();
            ByteList bl = str.getByteList();
            return BIO.memBuf(bl.bytes, bl.begin, bl.realSize);
        }
    }

    public static PKCS7 wrap(RubyClass klass, org.jruby.ext.openssl.impl.PKCS7 p7) {
        PKCS7 wrapped = new PKCS7(klass.getRuntime(), klass);
        wrapped.p7 = p7;
        return wrapped;
    }

    public static IRubyObject membio2str(Ruby runtime, BIO bio) {
        return runtime.newString(new ByteList(((MemBIO)bio).getMemCopy(), false));
    }

    private static List<X509AuxCertificate> x509_ary2sk(IRubyObject ary) {
        List<X509AuxCertificate> certs = new ArrayList<X509AuxCertificate>();
        RubyArray arr = (RubyArray)ary;
        for(int i = 0; i<arr.size(); i++) {
            certs.add(((X509Cert)arr.eltInternal(i)).getAuxCert());
        }
        return certs;
    }

    public static class ModuleMethods {
        @JRubyMethod(meta=true)
        public static IRubyObject read_smime(IRubyObject klass, IRubyObject arg) throws IOException {
            BIO in = obj2bio(arg);
            BIO[] out = new BIO[]{null};
            org.jruby.ext.openssl.impl.PKCS7 pkcs7 = new SMIME(Mime.DEFAULT).readPKCS7(in, out);
            if(pkcs7 == null) {
                throw new RaiseException(klass.getRuntime(), ((RubyModule)(((RubyModule)klass.getRuntime().getModule("OpenSSL")).getConstant("PKCS7"))).getClass("PKCS7Error"), null, false);
            }
            IRubyObject data = out[0] != null ? membio2str(klass.getRuntime(), out[0]) : klass.getRuntime().getNil();
            PKCS7 ret = wrap(((RubyModule)(((RubyModule)klass.getRuntime().getModule("OpenSSL")).getConstant("PKCS7"))).getClass("PKCS7"), pkcs7);
            ret.setData(data);
            return ret;
        }

        @JRubyMethod(meta=true, rest=true)
        public static IRubyObject write_smime(IRubyObject recv, IRubyObject[] args) {
            System.err.println("WARNING: un-implemented method called PKCS7#write_smime");
            return recv.getRuntime().getNil();
        }

        @JRubyMethod(meta=true, rest=true)
        public static IRubyObject sign(IRubyObject recv, IRubyObject[] args) throws Exception {
            Ruby runtime = recv.getRuntime();
            IRubyObject cert = runtime.getNil();
            IRubyObject key = runtime.getNil();
            IRubyObject data = runtime.getNil();
            IRubyObject certs = runtime.getNil();
            IRubyObject flags = runtime.getNil();

            switch(Arity.checkArgumentCount(runtime, args, 3, 5)) {
            case 5:
                flags = args[4];
            case 4:
                certs = args[3];
            case 3:
                cert = args[0];
                key = args[1];
                data = args[2];
            }

            X509AuxCertificate x509 = ((X509Cert)cert).getAuxCert();
            PrivateKey pkey = ((PKey)key).getPrivateKey();
            int flg = flags.isNil() ? 0 : RubyNumeric.fix2int(flags);

            BIO in = obj2bio(data);

            List<X509AuxCertificate> x509s = certs.isNil() 
                ? null 
                : x509_ary2sk(certs); 

            org.jruby.ext.openssl.impl.PKCS7 p7 = org.jruby.ext.openssl.impl.PKCS7.sign(x509, pkey, x509s, in, flg);
            PKCS7 ret = wrap(((RubyModule)(((RubyModule)recv.getRuntime().getModule("OpenSSL")).getConstant("PKCS7"))).getClass("PKCS7"), p7);
            ret.setData(data);

            return ret;
        }

        /** ossl_pkcs7_s_encrypt
         *
         */
        @JRubyMethod(meta=true, rest=true)
        public static IRubyObject encrypt(IRubyObject recv, IRubyObject[] args) throws Exception {
            IRubyObject certs, data, cipher = recv.getRuntime().getNil(), flags  = recv.getRuntime().getNil();
            javax.crypto.Cipher ciph = null;
            switch(Arity.checkArgumentCount(recv.getRuntime(), args, 2, 4)) {
            case 4:
                flags = args[3];
            case 3:
                cipher = args[2];
            }
            data = args[1];
            certs = args[0];
            
            if(cipher.isNil()) {
                ciph = javax.crypto.Cipher.getInstance("RC2/CBC/PKCS5Padding");
            } else {
                ciph = ((Cipher)cipher).getCipher();
            }

            int flg = flags.isNil() ? 0 : RubyNumeric.fix2int(flags);
            byte[] in = data.convertToString().getBytes();
            List<X509AuxCertificate> x509s = x509_ary2sk(certs);
            org.jruby.ext.openssl.impl.PKCS7 p7 = org.jruby.ext.openssl.impl.PKCS7.encrypt(x509s, in, ciph, flg);
            PKCS7 ret = wrap(((RubyModule)(((RubyModule)recv.getRuntime().getModule("OpenSSL")).getConstant("PKCS7"))).getClass("PKCS7"), p7);
            ret.setData(data);

            return ret;
        }
    }

    public PKCS7(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private org.jruby.ext.openssl.impl.PKCS7 p7;

    public void setData(IRubyObject object) {
        setInstanceVariable("@data", object);
    }
    
    public IRubyObject getData() {
        return getInstanceVariable("@data");
    }
    
    @JRubyMethod(name="initialize", rest=true)
    public IRubyObject _initialize(IRubyObject[] args) throws Exception {
        IRubyObject arg = null;
        if(Arity.checkArgumentCount(getRuntime(), args, 0, 1) == 0) {
            return this;
        }
        arg = args[0];

        arg = OpenSSLImpl.to_der_if_possible(arg);
        BIO input = obj2bio(arg);
        p7 = org.jruby.ext.openssl.impl.PKCS7.readPEM(input);
        if(p7 == null) {
            input.reset();
            p7 = org.jruby.ext.openssl.impl.PKCS7.fromASN1(input);
        }

        setData(getRuntime().getNil());
        return this;
    }

    @JRubyMethod
    public IRubyObject initialize_copy(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#init_copy");
        return this;
    }

    @JRubyMethod(name="type=")
    public IRubyObject set_type(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#type=");
        return getRuntime().getNil();
    }

    @JRubyMethod(name="type")
    public IRubyObject get_type() {
        if(p7.isSigned()) {
            return getRuntime().newSymbol("signed");
        }
        if(p7.isEncrypted()) {
            return getRuntime().newSymbol("encrypted");
        }
        if(p7.isEnveloped()) {
            return getRuntime().newSymbol("enveloped");
        }
        if(p7.isSignedAndEnveloped()) {
            return getRuntime().newSymbol("signedAndEnveloped");
        }
        if(p7.isData()) {
            return getRuntime().newSymbol("data");
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="detached=")
    public IRubyObject set_detached(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#detached=");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject detached() {
        System.err.println("WARNING: un.implemented method called PKCS7#detached");
        return getRuntime().getNil();
    }

    @JRubyMethod(name="detached?")
    public IRubyObject detached_p() {
        System.err.println("WARNING: un.implemented method called PKCS7#detached?");
        return getRuntime().getNil();
    }

    @JRubyMethod(name="cipher=")
    public IRubyObject set_cipher(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#cipher=");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject add_signer(IRubyObject obj) {
        SignerInfoWithPkey p7si = ((SignerInfo)obj).getSignerInfo().dup();

        p7.addSigner(p7si);
        // TODO: Handle exception here

        if(p7.isSigned()) {
            p7si.addSignedAttribute(ASN1Registry.NID_pkcs9_contentType, ASN1Registry.nid2obj(ASN1Registry.NID_pkcs7_data));
        }

        return this;
    }

    /** ossl_pkcs7_get_signer
     * 
     * This seems to return a list of SignerInfo objects.
     *
     */
    @JRubyMethod
    public IRubyObject signers() {
        Collection<SignerInfoWithPkey> sk = p7.getSignerInfo();
        RubyArray ary = getRuntime().newArray(sk.size());
        for(SignerInfoWithPkey si : sk) {
            ary.append(SignerInfo.create(getRuntime(), si));
        }
        return ary;
    }

    @JRubyMethod
    public IRubyObject add_recipient(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#add_recipient");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject recipients() {
        Collection<RecipInfo> sk = null;

        if(p7.isEnveloped()) {
            sk = p7.getEnveloped().getRecipientInfo();
        } else if(p7.isSignedAndEnveloped()) {
            sk = p7.getSignedAndEnveloped().getRecipientInfo();
        } else {
            sk = null;
        }
        if(sk == null) {
            return getRuntime().newArray();
        }

        RubyArray ary = getRuntime().newArray(sk.size());
        for(RecipInfo ri : sk) {
            ary.append(RecipientInfo.create(getRuntime(), ri));
        }
        return ary;
    }

    @JRubyMethod
    public IRubyObject add_certificate(IRubyObject obj) {
        p7.addCertificate(((X509Cert)obj).getAuxCert());
        return this;
    }

    @JRubyMethod(name="certificates=")
    public IRubyObject set_certificates(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#certificates=");
        return getRuntime().getNil();
    }

    private Collection<X509AuxCertificate> getCertificates() {
        Collection<X509AuxCertificate> certs;
        int i = p7.getType();
        switch(i) {
        case ASN1Registry.NID_pkcs7_signed:
            certs = p7.getSign().getCert();
            break;
        case ASN1Registry.NID_pkcs7_signedAndEnveloped:
            certs = p7.getSignedAndEnveloped().getCert();
            break;
        default:
            certs = new HashSet<X509AuxCertificate>();
            break;
        }
        return certs;
    }

    private RubyArray certsToArray(Collection<X509AuxCertificate> certs) throws Exception {
        RubyArray ary = getRuntime().newArray(certs.size());
        for(X509AuxCertificate x509 : certs) {
            ary.append(X509Cert.wrap(getRuntime(), x509));
        }
        return ary;
    }

    @JRubyMethod
    public IRubyObject certificates() throws Exception {
        return certsToArray(getCertificates());
    }

    @JRubyMethod
    public IRubyObject add_crl(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#add_crl");
        return getRuntime().getNil();
    }

    @JRubyMethod(name="crls=")
    public IRubyObject set_crls(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#crls=");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject crls() {
        System.err.println("WARNING: un.implemented method called PKCS7#crls");
        return getRuntime().getNil();
    }

    @JRubyMethod(name={"add_data", "data="})
    public IRubyObject add_data(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#add_data");
        return getRuntime().getNil();
    }

    @JRubyMethod(rest=true)
    public IRubyObject verify(IRubyObject[] args) throws Exception {
        IRubyObject certs = null;
        IRubyObject store = null;
        IRubyObject indata = getRuntime().getNil();
        IRubyObject flags = getRuntime().getNil();
        
        switch(Arity.checkArgumentCount(getRuntime(), args, 2, 4)) {
        case 4:
            flags = args[3];
        case 3:
            indata = args[2];
        default:
            store = args[1];
            certs = args[0];
        }
        int flg = flags.isNil() ? 0 : RubyNumeric.fix2int(flags);

        if(indata.isNil()) {
            indata = getData();
        }

        BIO in = indata.isNil() ? null : obj2bio(indata);

        List<X509AuxCertificate> x509s = certs.isNil() 
            ? null 
            : x509_ary2sk(certs); 

        Store x509st = ((X509Store)store).getStore();
        BIO out = BIO.mem();

        boolean result = false;
        try {
            p7.verify(x509s, x509st, in, out, flg);
            result = true;
        } catch(NotVerifiedPKCS7Exception e) {
            result = false;
        } catch(PKCS7Exception e) {
            System.err.println(e.toString());
            e.printStackTrace();
            // TODO: throw exception if it's a bad thingy here
            result = false;
        }

        IRubyObject data = membio2str(getRuntime(), out);
        setData(data);

        return result ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @JRubyMethod(rest=true)
    public IRubyObject decrypt(IRubyObject[] args) {
        IRubyObject flags = getRuntime().getNil();
        if(Arity.checkArgumentCount(getRuntime(), args, 2, 3) == 3) {
            flags = args[2];
        }
        IRubyObject pkey = args[0];
        IRubyObject cert = args[1];
        PrivateKey key = ((PKey)pkey).getPrivateKey();
        X509AuxCertificate x509 = ((X509Cert)cert).getAuxCert();
        int flg = flags.isNil() ? 0 : RubyNumeric.fix2int(flags);

        BIO out = BIO.mem();
        p7.decrypt(key, x509, out, flg);

        return membio2str(getRuntime(), out);
    }

    @JRubyMethod(name={"to_pem","to_s"})
    public IRubyObject to_pem() throws Exception {
        System.err.println("WARNING: un-implemented method called PKCS7#to_pem");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject to_der() throws IOException {
        return getRuntime().newString(new ByteList(p7.toASN1(), false));
    }

    public static class SignerInfo extends RubyObject {
        private static ObjectAllocator SIGNERINFO_ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new SignerInfo(runtime, klass);
            }
        };
    
        public static void createSignerInfo(Ruby runtime, RubyModule mPKCS7) {
            RubyClass cPKCS7Signer = mPKCS7.defineClassUnder("SignerInfo",runtime.getObject(),SIGNERINFO_ALLOCATOR);
            mPKCS7.defineConstant("Signer",cPKCS7Signer);

            cPKCS7Signer.defineAnnotatedMethods(SignerInfo.class);
        }

        public static SignerInfo create(Ruby runtime, SignerInfoWithPkey info) {
            SignerInfo sinfo = new SignerInfo(runtime, (RubyClass)(((RubyModule)(runtime.getModule("OpenSSL").getConstant("PKCS7"))).getConstant("SignerInfo")));
            sinfo.initWithSignerInformation(info);
            return sinfo;
        }

        public SignerInfo(Ruby runtime, RubyClass type) {
            super(runtime,type);
        }

        private SignerInfoWithPkey info;

        private void initWithSignerInformation(SignerInfoWithPkey info) {
            this.info = info;
        }

        SignerInfoWithPkey getSignerInfo() {
            return info;
        }

        @JRubyMethod
        public IRubyObject initialize(IRubyObject arg1, IRubyObject arg2, IRubyObject arg3) {
            System.err.println("WARNING: un-implemented method called SignerInfo#initialize");
            return this;
        }


        @JRubyMethod(name={"issuer","name"})
        public IRubyObject issuer() {
            return X509Name.create(getRuntime(), info.getIssuerAndSerialNumber().getName());
        }

        @JRubyMethod
        public IRubyObject serial() {
            return RubyBignum.bignorm(getRuntime(), info.getIssuerAndSerialNumber().getCertificateSerialNumber().getValue());
        }

        @JRubyMethod
        public IRubyObject signed_time() {
            System.err.println("WARNING: un-implemented method called SignerInfo#signed_time");
            return getRuntime().getNil();
        }
    }

    public static class RecipientInfo extends RubyObject {
        private static ObjectAllocator RECIPIENTINFO_ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new RecipientInfo(runtime, klass);
            }
        };
    
        public static void createRecipientInfo(Ruby runtime, RubyModule mPKCS7) {
            RubyClass cPKCS7Recipient = mPKCS7.defineClassUnder("RecipientInfo",runtime.getObject(),RECIPIENTINFO_ALLOCATOR);

            cPKCS7Recipient.defineAnnotatedMethods(RecipientInfo.class);
        }

        public RecipientInfo(Ruby runtime, RubyClass type) {
            super(runtime,type);
        }


        public static RecipientInfo create(Ruby runtime, RecipInfo info) {
            RecipientInfo rinfo = new RecipientInfo(runtime, (RubyClass)(((RubyModule)(runtime.getModule("OpenSSL").getConstant("PKCS7"))).getConstant("RecipientInfo")));
            rinfo.initWithRecipientInformation(info);
            return rinfo;
        }

        private RecipInfo info;

        private void initWithRecipientInformation(RecipInfo info) {
            this.info = info;
        }

        @JRubyMethod
        public IRubyObject initialize(IRubyObject arg) {
            System.err.println("WARNING: un-implemented method called RecipientInfo#initialize");
            return this;
        }

        @JRubyMethod
        public IRubyObject issuer() {
            return X509Name.create(getRuntime(), info.getIssuerAndSerial().getName());
        }

        @JRubyMethod
        public IRubyObject serial() {
            return RubyBignum.bignorm(getRuntime(), info.getIssuerAndSerial().getCertificateSerialNumber().getValue());
        }

        @JRubyMethod
        public IRubyObject enc_key() {
            System.err.println("WARNING: un-implemented method called RecipientInfo#enc_key");
            return getRuntime().getNil();
        }
    }
}// PKCS7
