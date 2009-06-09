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

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyBignum;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class PKeyRSA extends PKey {
    private static ObjectAllocator PKEYRSA_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new PKeyRSA(runtime, klass);
        }
    };
    
    public static void createPKeyRSA(Ruby runtime, RubyModule mPKey) {
        RubyClass cRSA = mPKey.defineClassUnder("RSA",mPKey.getClass("PKey"),PKEYRSA_ALLOCATOR);
        RubyClass pkeyError = mPKey.getClass("PKeyError");
        mPKey.defineClassUnder("RSAError",pkeyError,pkeyError.getAllocator());

        cRSA.defineAnnotatedMethods(PKeyRSA.class);

        cRSA.setConstant("PKCS1_PADDING",runtime.newFixnum(1));
        cRSA.setConstant("SSLV23_PADDING",runtime.newFixnum(2));
        cRSA.setConstant("NO_PADDING",runtime.newFixnum(3));
        cRSA.setConstant("PKCS1_OAEP_PADDING",runtime.newFixnum(4));
   }

    public static RaiseException newRSAError(Ruby runtime, String message) {
        return new RaiseException(runtime, ((RubyModule)runtime.getModule("OpenSSL").getConstantAt("PKey")).getClass("RSAError"), message, true);
    }
   
    public PKeyRSA(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private transient volatile RSAPrivateCrtKey privKey;
    private transient volatile RSAPublicKey pubKey;
    
    // fields to hold individual RSAPublicKeySpec components. this allows
    // a public key to be constructed incrementally, as required by the
    // current implementation of Net::SSH.
    // (see net-ssh-1.1.2/lib/net/ssh/transport/ossl/buffer.rb #read_keyblob)
    private transient volatile BigInteger rsa_e;
    private transient volatile BigInteger rsa_n;

    private transient volatile BigInteger rsa_d;
    private transient volatile BigInteger rsa_p;
    private transient volatile BigInteger rsa_q;
    private transient volatile BigInteger rsa_dmp1;
    private transient volatile BigInteger rsa_dmq1;
    private transient volatile BigInteger rsa_iqmp;
    
    PublicKey getPublicKey() {
        return pubKey;
    }

    PrivateKey getPrivateKey() {
        return privKey;
    }

    String getAlgorithm() {
        return "RSA";
    }

    @JRubyMethod(name="generate", meta=true, rest=true)
    public static IRubyObject generate(IRubyObject recv, IRubyObject[] args) {
        BigInteger exp = RSAKeyGenParameterSpec.F4;
        if(Arity.checkArgumentCount(recv.getRuntime(),args,1,2) == 2) {
            if(args[1] instanceof RubyFixnum) {
                exp = BigInteger.valueOf(RubyNumeric.num2long(args[1]));
            } else {
                exp = ((RubyBignum)args[1]).getValue();
            }
        }       
        int keysize = RubyNumeric.fix2int(args[0]);
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(keysize, exp);
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",OpenSSLReal.PROVIDER);
            gen.initialize(spec);
            KeyPair pair = gen.generateKeyPair();
            PKeyRSA rsa = new PKeyRSA(recv.getRuntime(), (RubyClass)recv);
            rsa.privKey = (RSAPrivateCrtKey)(pair.getPrivate());
            rsa.pubKey = (RSAPublicKey)(pair.getPublic());
            return rsa;
        } catch(Exception e) {
            throw newRSAError(recv.getRuntime(), null);
        }
    }

    @JRubyMethod(frame=true, rest=true)
    public IRubyObject initialize(IRubyObject[] args, Block block) {
        IRubyObject arg;
        IRubyObject pass = null;
        char[] passwd = null;
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,0,2) == 0) {
        } else {
            arg = args[0];
            if(args.length > 1) {
                pass = args[1];
            }
            if(arg instanceof RubyFixnum) {
                int keyLen = RubyNumeric.fix2int(arg);
                BigInteger pubExp = RSAKeyGenParameterSpec.F4;
                if(null != pass && !pass.isNil()) {
                    pubExp = BigInteger.valueOf(RubyNumeric.num2long(pass));
                }
                try {
                    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",OpenSSLReal.PROVIDER);
                    gen.initialize(new RSAKeyGenParameterSpec(keyLen,pubExp));
                    KeyPair pair = gen.generateKeyPair();
                    privKey = (RSAPrivateCrtKey)(pair.getPrivate());
                    pubKey = (RSAPublicKey)(pair.getPublic());
                } catch(Exception e) {
                    throw newRSAError(getRuntime(), null);
                }
            } else {
                if(pass != null && !pass.isNil()) {
                    passwd = pass.toString().toCharArray();
                }
                String input = arg.toString();

                Object val = null;
                KeyFactory fact = null;
                try {
                    fact = KeyFactory.getInstance("RSA", OpenSSLReal.PROVIDER);
                } catch(Exception e) {
                    throw getRuntime().newLoadError("unsupported key algorithm (RSA)");
                }

                if(null == val) {
                    try {
                        val = PEMInputOutput.readRSAPrivateKey(new StringReader(input),passwd);
                    } catch(Exception e) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        val = PEMInputOutput.readRSAPublicKey(new StringReader(input),passwd);
                    } catch(Exception e) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        val = PEMInputOutput.readRSAPubKey(new StringReader(input),passwd);
                    } catch(Exception e) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        DERSequence seq = (DERSequence)(new ASN1InputStream(ByteList.plain(input)).readObject());
                        if(seq.size() == 9) {
                            BigInteger mod = ((DERInteger)seq.getObjectAt(1)).getValue();
                            BigInteger pubexp = ((DERInteger)seq.getObjectAt(2)).getValue();
                            BigInteger privexp = ((DERInteger)seq.getObjectAt(3)).getValue();
                            BigInteger primep = ((DERInteger)seq.getObjectAt(4)).getValue();
                            BigInteger primeq = ((DERInteger)seq.getObjectAt(5)).getValue();
                            BigInteger primeep = ((DERInteger)seq.getObjectAt(6)).getValue();
                            BigInteger primeeq = ((DERInteger)seq.getObjectAt(7)).getValue();
                            BigInteger crtcoeff = ((DERInteger)seq.getObjectAt(8)).getValue();
                            val = fact.generatePrivate(new RSAPrivateCrtKeySpec(mod,pubexp,privexp,primep,primeq,primeep,primeeq,crtcoeff));
                        } else {
                            val = null;
                        }
                    } catch(Exception ex) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        DERSequence seq = (DERSequence)(new ASN1InputStream(ByteList.plain(input)).readObject());
                        if(seq.size() == 2) {
                            BigInteger mod = ((DERInteger)seq.getObjectAt(0)).getValue();
                            BigInteger pubexp = ((DERInteger)seq.getObjectAt(1)).getValue();
                            val = fact.generatePublic(new RSAPublicKeySpec(mod,pubexp));
                        } else {
                            val = null;
                        }
                    } catch(Exception ex) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        val = fact.generatePublic(new X509EncodedKeySpec(ByteList.plain(input)));
                    } catch(Exception e) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        val = fact.generatePrivate(new PKCS8EncodedKeySpec(ByteList.plain(input)));
                    } catch(Exception e) {
                        val = null;
                    }
                }
                if(null == val) {
                    throw newRSAError(getRuntime(), "Neither PUB key nor PRIV key:");
                }

                if(val instanceof KeyPair) {
                    privKey = (RSAPrivateCrtKey)(((KeyPair)val).getPrivate());
                    pubKey = (RSAPublicKey)(((KeyPair)val).getPublic());
                } else if(val instanceof RSAPrivateCrtKey) {
                    privKey = (RSAPrivateCrtKey)val;
                    try {
                        pubKey = (RSAPublicKey)(fact.generatePublic(new RSAPublicKeySpec(privKey.getModulus(),privKey.getPublicExponent())));
                    } catch(Exception e) {
                        throw newRSAError(getRuntime(), "Something rotten with private key");
                    }
                } else if(val instanceof RSAPublicKey) {
                    pubKey = (RSAPublicKey)val;
                    privKey = null;
                } else {
                    throw newRSAError(getRuntime(), "Neither PUB key nor PRIV key:");
                }
            }
        }

        return this;
    }

    @JRubyMethod(name="public?")
    public IRubyObject public_p() {
        return pubKey != null ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @JRubyMethod(name="private?")
    public IRubyObject private_p() {
        return privKey != null ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @JRubyMethod
    public IRubyObject to_der() throws Exception {
        if(pubKey != null && privKey == null) {
            ASN1EncodableVector v1 = new ASN1EncodableVector();
            v1.add(new DERInteger(pubKey.getModulus()));
            v1.add(new DERInteger(pubKey.getPublicExponent()));
            return RubyString.newString(getRuntime(), new DERSequence(v1).getEncoded());
        } else {
            ASN1EncodableVector v1 = new ASN1EncodableVector();
            v1.add(new DERInteger(0));
            v1.add(new DERInteger(privKey.getModulus()));
            v1.add(new DERInteger(privKey.getPublicExponent()));
            v1.add(new DERInteger(privKey.getPrivateExponent()));
            v1.add(new DERInteger(privKey.getPrimeP()));
            v1.add(new DERInteger(privKey.getPrimeQ()));
            v1.add(new DERInteger(privKey.getPrimeExponentP()));
            v1.add(new DERInteger(privKey.getPrimeExponentQ()));
            v1.add(new DERInteger(privKey.getCrtCoefficient()));
            return RubyString.newString(getRuntime(), new DERSequence(v1).getEncoded());
        }
    }

    @JRubyMethod
    public IRubyObject public_key() {
        PKeyRSA val = new PKeyRSA(getRuntime(),getMetaClass().getRealClass());
        val.privKey = null;
        val.pubKey = this.pubKey;
        return val;
    }

    private static void addSplittedAndFormatted(int keylen, StringBuilder result, BigInteger value) {
        String v = value.toString(16);
        if((v.length() % 2) != 0) {
            v = "0" + v;
        }
        String sep = "";
        for(int i = 0; i<v.length(); i+=2) {
            result.append(sep);
            if((i % 30) == 0) {
                result.append("\n    ");
            }
            result.append(v.substring(i, i+2));
            sep = ":";
        }
        result.append("\n");
    }

    @JRubyMethod
    public IRubyObject params() throws Exception {
        ThreadContext ctx = getRuntime().getCurrentContext();
        RubyHash hash = RubyHash.newHash(getRuntime());
        if(privKey != null) {
            hash.op_aset(ctx, getRuntime().newString("iqmp"), BN.newBN(getRuntime(), privKey.getCrtCoefficient()));
            hash.op_aset(ctx, getRuntime().newString("n"), BN.newBN(getRuntime(), privKey.getModulus()));
            hash.op_aset(ctx, getRuntime().newString("d"), BN.newBN(getRuntime(), privKey.getPrivateExponent()));
            hash.op_aset(ctx, getRuntime().newString("p"), BN.newBN(getRuntime(), privKey.getPrimeP()));
            hash.op_aset(ctx, getRuntime().newString("e"), BN.newBN(getRuntime(), privKey.getPublicExponent()));
            hash.op_aset(ctx, getRuntime().newString("q"), BN.newBN(getRuntime(), privKey.getPrimeQ()));
            hash.op_aset(ctx, getRuntime().newString("dmq1"), BN.newBN(getRuntime(), privKey.getPrimeExponentQ()));
            hash.op_aset(ctx, getRuntime().newString("dmp1"), BN.newBN(getRuntime(), privKey.getPrimeExponentP()));
            
        } else {
            hash.op_aset(ctx, getRuntime().newString("iqmp"), BN.newBN(getRuntime(), BigInteger.ZERO));
            hash.op_aset(ctx, getRuntime().newString("n"), BN.newBN(getRuntime(), pubKey.getModulus()));
            hash.op_aset(ctx, getRuntime().newString("d"), BN.newBN(getRuntime(), BigInteger.ZERO));
            hash.op_aset(ctx, getRuntime().newString("p"), BN.newBN(getRuntime(), BigInteger.ZERO));
            hash.op_aset(ctx, getRuntime().newString("e"), BN.newBN(getRuntime(), pubKey.getPublicExponent()));
            hash.op_aset(ctx, getRuntime().newString("q"), BN.newBN(getRuntime(), BigInteger.ZERO));
            hash.op_aset(ctx, getRuntime().newString("dmq1"), BN.newBN(getRuntime(), BigInteger.ZERO));
            hash.op_aset(ctx, getRuntime().newString("dmp1"), BN.newBN(getRuntime(), BigInteger.ZERO));
        }
        return hash;
    }

    @JRubyMethod
    public IRubyObject to_text() throws Exception {
        StringBuilder result = new StringBuilder();
        if(privKey != null) {
            int len = privKey.getModulus().bitLength();
            result.append("Private-Key: (").append(len).append(" bit)").append("\n");
            result.append("modulus:");
            addSplittedAndFormatted(len, result, privKey.getModulus());
            result.append("publicExponent: ").append(privKey.getPublicExponent()).append(" (0x").append(privKey.getPublicExponent().toString(16)).append(")\n");
            result.append("privateExponent:");
            addSplittedAndFormatted(len, result, privKey.getPrivateExponent());
            result.append("prime1:");
            addSplittedAndFormatted(len, result, privKey.getPrimeP());
            result.append("prime2:");
            addSplittedAndFormatted(len, result, privKey.getPrimeQ());
            result.append("exponent1:");
            addSplittedAndFormatted(len, result, privKey.getPrimeExponentP());
            result.append("exponent2:");
            addSplittedAndFormatted(len, result, privKey.getPrimeExponentQ());
            result.append("coefficient:");
            addSplittedAndFormatted(len, result, privKey.getCrtCoefficient());
        } else {
            int len = pubKey.getModulus().bitLength();
            result.append("Modulus (").append(len).append(" bit):");
            addSplittedAndFormatted(len, result, pubKey.getModulus());
            result.append("Exponent: ").append(pubKey.getPublicExponent()).append(" (0x").append(pubKey.getPublicExponent().toString(16)).append(")\n");
        }
        return getRuntime().newString(result.toString());
    }

    @JRubyMethod(name={"export", "to_pem", "to_s"}, rest=true)
    public IRubyObject export(IRubyObject[] args) throws Exception {
        StringWriter w = new StringWriter();
        org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,0,2);
        char[] passwd = null;
        String algo = null;
        if(args.length > 0 && !args[0].isNil()) {
            algo = ((org.jruby.ext.openssl.Cipher)args[0]).getAlgorithm();
            if(args.length > 1 && !args[1].isNil()) {
                passwd = args[1].toString().toCharArray();
            }
        }
        if(privKey != null) {
            PEMInputOutput.writeRSAPrivateKey(w,privKey,algo,passwd);
        } else {
            PEMInputOutput.writeRSAPublicKey(w,pubKey);
        }
        w.close();
        return getRuntime().newString(w.toString());
    }

    private String getPadding(int padding) {
        if(padding < 1 || padding > 4) {
            throw newRSAError(getRuntime(), null);
        }

        String p = "/NONE/PKCS1Padding";
        if(padding == 3) {
            p = "/NONE/NoPadding";
        } else if(padding == 4) {
            p = "/NONE/OAEPWithMD5AndMGF1Padding";
        } else if(padding == 2) {
            p = "/NONE/ISO9796-1Padding";
        }
        return p;
    }        

    @JRubyMethod(rest=true)
    public IRubyObject private_encrypt(IRubyObject[] args) throws Exception {
        int padding = 1;
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,1,2) == 2 && !args[1].isNil()) {
            padding = RubyNumeric.fix2int(args[1]);
        }
        String p = getPadding(padding);

        RubyString buffer = args[0].convertToString();
        if(privKey == null) {
            throw newRSAError(getRuntime(), "private key needed.");
        }

        Cipher engine = Cipher.getInstance("RSA"+p,OpenSSLReal.PROVIDER);
        engine.init(Cipher.ENCRYPT_MODE,privKey);
        byte[] outp = engine.doFinal(buffer.getBytes());
        return RubyString.newString(getRuntime(), outp);
    }

    @JRubyMethod(rest=true)
    public IRubyObject private_decrypt(IRubyObject[] args) throws Exception {
        int padding = 1;
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,1,2) == 2 && !args[1].isNil()) {
            padding = RubyNumeric.fix2int(args[1]);
        }
        String p = getPadding(padding);

        RubyString buffer = args[0].convertToString();
        if(privKey == null) {
            throw newRSAError(getRuntime(), "private key needed.");
        }

        Cipher engine = Cipher.getInstance("RSA"+p,OpenSSLReal.PROVIDER);
        engine.init(Cipher.DECRYPT_MODE,privKey);
        byte[] outp = engine.doFinal(buffer.getBytes());
        return RubyString.newString(getRuntime(), outp);
    }

    @JRubyMethod(rest=true)
    public IRubyObject public_encrypt(IRubyObject[] args) throws Exception {
        int padding = 1;
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,1,2) == 2 && !args[1].isNil()) {
            padding = RubyNumeric.fix2int(args[1]);
        }
        String p = getPadding(padding);

        RubyString buffer = args[0].convertToString();
        Cipher engine = Cipher.getInstance("RSA"+p,OpenSSLReal.PROVIDER);
        engine.init(Cipher.ENCRYPT_MODE,pubKey);
        byte[] outp = engine.doFinal(buffer.getBytes());
        return RubyString.newString(getRuntime(), outp);
    }

    @JRubyMethod(rest=true)
    public IRubyObject public_decrypt(IRubyObject[] args) throws Exception {
        int padding = 1;
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,1,2) == 2 && !args[1].isNil()) {
            padding = RubyNumeric.fix2int(args[1]);
        }
        String p = getPadding(padding);

        RubyString buffer = args[0].convertToString();
        Cipher engine = Cipher.getInstance("RSA"+p,OpenSSLReal.PROVIDER);
        engine.init(Cipher.DECRYPT_MODE,pubKey);
        byte[] outp = engine.doFinal(buffer.getBytes());
        return RubyString.newString(getRuntime(), outp);
    }

    @JRubyMethod(name="d=")
    public synchronized IRubyObject set_d(IRubyObject value) {
        if (privKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        rsa_d = BN.getBigInteger(value);
        generatePrivateKeyIfParams();
        return value;
    }

    @JRubyMethod(name="p=")
    public synchronized IRubyObject set_p(IRubyObject value) {
        if (privKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        rsa_p = BN.getBigInteger(value);
        generatePrivateKeyIfParams();
        return value;
    }

    @JRubyMethod(name="q=")
    public synchronized IRubyObject set_q(IRubyObject value) {
        if (privKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        rsa_q = BN.getBigInteger(value);
        generatePrivateKeyIfParams();
        return value;
    }

    @JRubyMethod(name="dmp1=")
    public synchronized IRubyObject set_dmp1(IRubyObject value) {
        if (privKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        rsa_dmp1 = BN.getBigInteger(value);
        generatePrivateKeyIfParams();
        return value;
    }

    @JRubyMethod(name="dmq1=")
    public synchronized IRubyObject set_dmq1(IRubyObject value) {
        if (privKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        rsa_dmq1 = BN.getBigInteger(value);
        generatePrivateKeyIfParams();
        return value;
    }

    @JRubyMethod(name="iqmp=")
    public synchronized IRubyObject set_iqmp(IRubyObject value) {
        if (privKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        rsa_iqmp = BN.getBigInteger(value);
        generatePrivateKeyIfParams();
        return value;
    }

    @JRubyMethod(name="iqmp")
    public synchronized IRubyObject get_iqmp() {
        BigInteger iqmp = null;
        if (privKey != null) {
            iqmp = privKey.getCrtCoefficient();
        } else {
            iqmp = rsa_iqmp;
        }
        if (iqmp != null) {
            return BN.newBN(getRuntime(), iqmp);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="dmp1")
    public synchronized IRubyObject get_dmp1() {
        BigInteger dmp1 = null;
        if (privKey != null) {
            dmp1 = privKey.getPrimeExponentP();
        } else {
            dmp1 = rsa_dmp1;
        }
        if (dmp1 != null) {
            return BN.newBN(getRuntime(), dmp1);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="dmq1")
    public synchronized IRubyObject get_dmq1() {
        BigInteger dmq1 = null;
        if (privKey != null) {
            dmq1 = privKey.getPrimeExponentQ();
        } else {
            dmq1 = rsa_dmq1;
        }
        if (dmq1 != null) {
            return BN.newBN(getRuntime(), dmq1);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="d")
    public synchronized IRubyObject get_d() {
        BigInteger d = null;
        if (privKey != null) {
            d = privKey.getPrivateExponent();
        } else {
            d = rsa_d;
        }
        if (d != null) {
            return BN.newBN(getRuntime(), d);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="p")
    public synchronized IRubyObject get_p() {
        BigInteger p = null;
        if (privKey != null) {
            p = privKey.getPrimeP();
        } else {
            p = rsa_p;
        }
        if (p != null) {
            return BN.newBN(getRuntime(), p);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="q")
    public synchronized IRubyObject get_q() {
        BigInteger q = null;
        if (privKey != null) {
            q = privKey.getPrimeQ();
        } else {
            q = rsa_q;
        }
        if (q != null) {
            return BN.newBN(getRuntime(), q);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="e")
    public synchronized IRubyObject get_e() {
        RSAPublicKey key;
        BigInteger e;
        if ((key = pubKey) != null) {
            e = key.getPublicExponent();
        } else if(privKey != null) {
            e = privKey.getPublicExponent();
        } else {
            e = rsa_e;
        }
        if (e != null) {
            return BN.newBN(getRuntime(), e);
        }
        return getRuntime().getNil();
    }
    
    @JRubyMethod(name="e=")
    public synchronized IRubyObject set_e(IRubyObject value) {
        rsa_e = BN.getBigInteger(value);

        if(privKey == null) {
            generatePrivateKeyIfParams();
        }
        if(pubKey == null) {
            generatePublicKeyIfParams();
        }
        return value;
    }
    
    @JRubyMethod(name="n")
    public synchronized IRubyObject get_n() {
        RSAPublicKey key;
        BigInteger n;
        if ((key = pubKey) != null) {
            n = key.getModulus();
        } else if(privKey != null) {
            n = privKey.getModulus();
        } else {
            n = rsa_n;
        }
        if (n != null) {
            return BN.newBN(getRuntime(), n);
        }
        return getRuntime().getNil();
    }
    
    @JRubyMethod(name="n=")
    public synchronized IRubyObject set_n(IRubyObject value) {
        rsa_n = BN.getBigInteger(value);

        if(privKey == null) {
            generatePrivateKeyIfParams();
        }
        if(pubKey == null) {
            generatePublicKeyIfParams();
        }
        return value;
    }
    
    private void generatePublicKeyIfParams() {
        if (pubKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        BigInteger e, n;
        if ((e = rsa_e) != null && (n = rsa_n) != null) {
            KeyFactory fact;
            try {
                fact = KeyFactory.getInstance("RSA", OpenSSLReal.PROVIDER);
            } catch(Exception ex) {
                throw getRuntime().newLoadError("unsupported key algorithm (RSA)");
            }
            try {
                pubKey = (RSAPublicKey)fact.generatePublic(new RSAPublicKeySpec(n, e));
            } catch (InvalidKeySpecException ex) {
                throw newRSAError(getRuntime(), "invalid parameters");
            }
            rsa_e = null;
            rsa_n = null;
        }
    }
    
    private void generatePrivateKeyIfParams() {
        if (privKey != null) {
            throw newRSAError(getRuntime(), "illegal modification");
        }
        if (rsa_e != null && rsa_n != null && rsa_p != null && rsa_q != null && rsa_d != null && rsa_dmp1 != null && rsa_dmq1 != null && rsa_iqmp != null) {
            KeyFactory fact;
            try {
                fact = KeyFactory.getInstance("RSA", OpenSSLReal.PROVIDER);
            } catch(Exception ex) {
                throw getRuntime().newLoadError("unsupported key algorithm (RSA)");
            }
            try {
                privKey = (RSAPrivateCrtKey)fact.generatePrivate(new RSAPrivateCrtKeySpec(rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp));
            } catch (InvalidKeySpecException ex) {
                throw newRSAError(getRuntime(), "invalid parameters");
            }
            rsa_n = null;
            rsa_e = null;
            rsa_d = null;
            rsa_p = null;
            rsa_q = null;
            rsa_dmp1 = null;
            rsa_dmq1 = null;
            rsa_iqmp = null;
        }
    }
}// PKeyRSA
