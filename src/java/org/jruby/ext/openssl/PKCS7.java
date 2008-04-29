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
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.ext.openssl.x509store.StoreContext;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;

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
    public static class ModuleMethods {
        @JRubyMethod(meta=true)
        public static IRubyObject read_smime(IRubyObject recv, IRubyObject arg) {
            System.err.println("WARNING: un-implemented method called PKCS7#read_smime");
            return recv.getRuntime().getNil();
        }

        @JRubyMethod(meta=true, rest=true)
        public static IRubyObject write_smime(IRubyObject recv, IRubyObject[] args) {
            System.err.println("WARNING: un-implemented method called PKCS7#write_smime");
            return recv.getRuntime().getNil();
        }

        @JRubyMethod(meta=true, rest=true)
        public static IRubyObject sign(IRubyObject recv, IRubyObject[] args) throws Exception {
            IRubyObject cert = recv.getRuntime().getNil();
            IRubyObject key = recv.getRuntime().getNil();
            IRubyObject data = recv.getRuntime().getNil();
            IRubyObject certs = recv.getRuntime().getNil();
            //IRubyObject flags = recv.getRuntime().getNil();
            org.jruby.runtime.Arity.checkArgumentCount(recv.getRuntime(),args,3,5);
            switch(args.length) {
            case 5:
                //flags = args[4];
            case 4:
                certs = args[3];
            case 3:
                cert = args[0];
                key = args[1];
                data = args[2];
            }

            X509AuxCertificate x509 = ((X509Cert)cert).getAuxCert();
            PrivateKey pkey = ((PKey)key).getPrivateKey();
            List<X509AuxCertificate> x509s = null;
            if(!certs.isNil()) {
                x509s = new ArrayList<X509AuxCertificate>();
                for(Iterator iter = ((RubyArray)certs).getList().iterator();iter.hasNext();) {
                    x509s.add(((X509Cert)iter.next()).getAuxCert());
                }
                x509s.add(x509);
            }

            final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSigner(pkey,x509,"1.3.14.3.2.26"); //SHA1 OID
            if(x509s != null) {
                CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(x509s), OpenSSLReal.PROVIDER);
                gen.addCertificatesAndCRLs(store);
            }

            final CMSSignedData[] result = new CMSSignedData[1];
            final byte[] bdata = data.convertToString().getBytes();
            OpenSSLReal.doWithBCProvider(new Runnable() {
                    public void run() {
                        try {
                            result[0] = gen.generate(new CMSProcessableByteArray(bdata), "BC");
                        } catch(GeneralSecurityException e) {
                        } catch(CMSException e) {
                        }
                    }
                });

            CMSSignedData sdata = result[0];
        
            PKCS7 ret = new PKCS7(recv.getRuntime(),((RubyClass)((RubyModule)(recv.getRuntime().getModule("OpenSSL").getConstant("PKCS7"))).getConstant("PKCS7")));
            ret.setInstanceVariable("@data",recv.getRuntime().getNil());
            ret.setInstanceVariable("@error_string",recv.getRuntime().getNil());
            ret.signedData = sdata;

            return ret;
        }

        @JRubyMethod(meta=true, rest=true)
        public static IRubyObject encrypt(IRubyObject recv, IRubyObject[] args) {
            System.err.println("WARNING: un-implemented method called PKCS7#encrypt");
            return recv.getRuntime().getNil();
        }
    }
    public PKCS7(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private CMSSignedData signedData;

    @JRubyMethod(name="initialize", rest=true)
    public IRubyObject _initialize(IRubyObject[] args) throws Exception {
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,0,1) == 0) {
            return this;
        }
        IRubyObject arg = OpenSSLImpl.to_der_if_possible(args[0]);
        byte[] b = arg.convertToString().getBytes();
        signedData = PEMInputOutput.readPKCS7(new InputStreamReader(new ByteArrayInputStream(b)),null);
        if(null == signedData) {
            signedData = new CMSSignedData(ContentInfo.getInstance(new ASN1InputStream(b).readObject()));
        }
        this.setInstanceVariable("@data",getRuntime().getNil());
        this.setInstanceVariable("@error_string",getRuntime().getNil());
        return this;
    }

    @JRubyMethod
    public IRubyObject initialize_copy(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#init_copy");
        if(this == obj) {
            return this;
        }
        checkFrozen();
        return this;
    }

    @JRubyMethod(name="type=")
    public IRubyObject set_type(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#type=");
        return getRuntime().getNil();
    }

    @JRubyMethod(name="type")
    public IRubyObject get_type() {
        System.err.println("WARNING: un.implemented method called PKCS7#type");
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
        System.err.println("WARNING: un.implemented method called PKCS7#add_signer");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject signers() {
        System.err.println("WARNING: un.implemented method called PKCS7#signers");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject add_recipient(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#add_recipient");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject recipients() {
        System.err.println("WARNING: un.implemented method called PKCS7#recipients");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject add_certificate(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#add_certificate");
        return getRuntime().getNil();
    }

    @JRubyMethod(name="certificates=")
    public IRubyObject set_certificates(IRubyObject obj) {
        System.err.println("WARNING: un.implemented method called PKCS7#certificates=");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject certificates() throws Exception {
        final CertStore[] result = new CertStore[1];
        OpenSSLReal.doWithBCProvider(new Runnable() {
                public void run() {
                    try {
                        result[0] = signedData.getCertificatesAndCRLs("Collection","BC");
                    } catch(GeneralSecurityException e) {
                    } catch(CMSException e) {
                    }
                }
            });
        CertStore cc = result[0];
        List<X509AuxCertificate> l = StoreContext.ensureAux(cc.getCertificates(null));
        List<IRubyObject> certs = new ArrayList<IRubyObject>(l.size());
        for(X509AuxCertificate c : l) {
            certs.add(X509Cert.wrap(getRuntime(), c));
        }
        return getRuntime().newArray(certs);
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
        IRubyObject certs;
        //IRubyObject store;
        IRubyObject indata = getRuntime().getNil();
        //IRubyObject flags = getRuntime().getNil();
        switch(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,2,4)) {
        case 4:
            //flags = args[3];
        case 3:
            indata = args[2];
        default:
            certs = args[0];
            //store = args[1];
        }
        
        if(indata.isNil()) {
            indata = getInstanceVariable("@data");
        }
        List<X509AuxCertificate> x509s = null;
        if(!certs.isNil()) {
            x509s = new ArrayList<X509AuxCertificate>();
            for(Iterator iter = ((RubyArray)certs).getList().iterator();iter.hasNext();) {
                x509s.add(((X509Cert)iter.next()).getAuxCert());
            }
        }

        CertStore _x509s = CertStore.getInstance("Collection", new CollectionCertStoreParameters(x509s),OpenSSLReal.PROVIDER);

        int verified = 0;

        SignerInformationStore  signers =  signedData.getSignerInfos();

        final CertStore[] result2 = new CertStore[1];
        OpenSSLReal.doWithBCProvider(new Runnable() {
                public void run() {
                    try {
                        result2[0] = signedData.getCertificatesAndCRLs("Collection","BC");
                    } catch(GeneralSecurityException e) {
                    } catch(CMSException e) {
                    }
                }
            });
        CertStore  cs = result2[0];
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
  
        while(it.hasNext()) {
            final SignerInformation   signer = (SignerInformation)it.next();
            System.err.println(signer.getSignedAttributes().toHashtable());

            Collection          certCollection = _x509s.getCertificates(signer.getSID());
            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = null;

            if(certIt.hasNext()) {
                cert = (X509AuxCertificate)certIt.next();
            }
            if(cert == null) {
                Collection          certCollection2 = cs.getCertificates(signer.getSID());
                Iterator        certIt2 = certCollection2.iterator();
                if(certIt2.hasNext()) {
                    cert = (X509Certificate)certIt2.next();
                }                
            }

            final boolean[] result = new boolean[]{false};
            final X509Certificate cert2 = cert;
            if(null != cert) {
                OpenSSLReal.doWithBCProvider(new Runnable() {
                        public void run() {
                            try {
                                result[0] = signer.verify(cert2, "BC");
                            } catch(GeneralSecurityException e) {
                            } catch(CMSException e) {
                            }
                        }
                    });
                if(result[0]) {
                    verified++;
                }
            }
        }

        return (verified != 0) ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @JRubyMethod(rest=true)
    public IRubyObject decrypt(IRubyObject[] args) {
        System.err.println("WARNING: un.implemented method called PKCS7#decrypt");
        return getRuntime().getNil();
    }

    @JRubyMethod(name={"to_pem","to_s"})
    public IRubyObject to_pem() throws Exception {
        StringWriter w = new StringWriter();
        PEMInputOutput.writePKCS7(w,signedData);
        w.close();
        return getRuntime().newString(w.toString());
    }

    @JRubyMethod
    public IRubyObject to_der() throws Exception {
        return RubyString.newString(getRuntime(), signedData.getEncoded());
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

        public SignerInfo(Ruby runtime, RubyClass type) {
            super(runtime,type);
        }

        @JRubyMethod
        public IRubyObject initialize(IRubyObject arg1, IRubyObject arg2, IRubyObject arg3) {
            System.err.println("WARNING: un-implemented method called SignerInfo#initialize");
            return this;
        }

        @JRubyMethod(name={"issuer","name"})
        public IRubyObject issuer() {
            System.err.println("WARNING: un-implemented method called SignerInfo#issuer");
            return getRuntime().getNil();
        }

        @JRubyMethod
        public IRubyObject serial() {
            System.err.println("WARNING: un-implemented method called SignerInfo#serial");
            return getRuntime().getNil();
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

        @JRubyMethod
        public IRubyObject initialize(IRubyObject arg) {
            System.err.println("WARNING: un-implemented method called RecipientInfo#initialize");
            return this;
        }

        @JRubyMethod
        public IRubyObject issuer() {
            System.err.println("WARNING: un-implemented method called RecipientInfo#issuer");
            return getRuntime().getNil();
        }

        @JRubyMethod
        public IRubyObject serial() {
            System.err.println("WARNING: un-implemented method called RecipientInfo#serial");
            return getRuntime().getNil();
        }

        @JRubyMethod
        public IRubyObject enc_key() {
            System.err.println("WARNING: un-implemented method called RecipientInfo#enc_key");
            return getRuntime().getNil();
        }
    }
}// PKCS7
