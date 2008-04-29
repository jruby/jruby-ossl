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
 * Copyright (C) 2007 Wiliam N Dortch <bill.dortch@gmail.com>
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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class PKeyDSA extends PKey {
    private static final long serialVersionUID = 2359742219218350277L;

    private static ObjectAllocator PKEYDSA_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new PKeyDSA(runtime, klass);
        }
    };
    
    public static void createPKeyDSA(Ruby runtime, RubyModule mPKey) {
        RubyClass cDSA = mPKey.defineClassUnder("DSA",mPKey.getClass("PKey"),PKEYDSA_ALLOCATOR);
        RubyClass pkeyError = mPKey.getClass("PKeyError");
        mPKey.defineClassUnder("DSAError",pkeyError,pkeyError.getAllocator());
        

        cDSA.defineAnnotatedMethods(PKeyDSA.class);
    }

    public static RaiseException newDSAError(Ruby runtime, String message) {
        return new RaiseException(runtime, ((RubyModule)runtime.getModule("OpenSSL").getConstantAt("PKey")).getClass("DSAError"), message, true);
    }
    
    public PKeyDSA(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private DSAPrivateKey privKey;
    private DSAPublicKey pubKey;
    
    // specValues holds individual DSAPublicKeySpec components. this allows
    // a public key to be constructed incrementally, as required by the
    // current implementation of Net::SSH.
    // (see net-ssh-1.1.2/lib/net/ssh/transport/ossl/buffer.rb #read_keyblob)
    private BigInteger[] specValues;
    
    private static final int SPEC_Y = 0;
    private static final int SPEC_P = 1;
    private static final int SPEC_Q = 2;
    private static final int SPEC_G = 3;
    

    PublicKey getPublicKey() {
        return pubKey;
    }

    PrivateKey getPrivateKey() {
        return privKey;
    }

    String getAlgorithm() {
        return "DSA";
    }

    @JRubyMethod(rest=true)
    public IRubyObject initialize(IRubyObject[] args) {
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
            } else {
                if(pass != null && !pass.isNil()) {
                    passwd = pass.toString().toCharArray();
                }
                String input = arg.toString();

                Object val = null;
                KeyFactory fact = null;
                try {
                    fact = KeyFactory.getInstance("DSA",OpenSSLReal.PROVIDER);
                } catch(NoSuchAlgorithmException e) {
                    throw getRuntime().newLoadError("unsupported key algorithm (DSA)");
                }
                if(null == val) {
                    try {
                        val = PEMInputOutput.readDSAPrivateKey(new StringReader(input),passwd);
                    } catch(Exception e3) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        val = PEMInputOutput.readDSAPublicKey(new StringReader(input),passwd);
                    } catch(Exception e3) {
                        val = null;
                    }
                }
                if(null == val) {
                    try {
                        val = PEMInputOutput.readDSAPubKey(new StringReader(input),passwd);
                    } catch(Exception e3) {
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
                    try {
                        val = fact.generatePublic(new X509EncodedKeySpec(ByteList.plain(input)));
                    } catch(Exception e) {
                        val = null;
                    }
                }
                if(null == val) {
                    throw newDSAError(getRuntime(), "Neither PUB key nor PRIV key:");
                }

                if(val instanceof KeyPair) {
                    privKey = (DSAPrivateKey)(((KeyPair)val).getPrivate());
                    pubKey = (DSAPublicKey)(((KeyPair)val).getPublic());
                } else if(val instanceof DSAPrivateKey) {
                    privKey = (DSAPrivateKey)val;
                } else if(val instanceof DSAPublicKey) {
                    pubKey = (DSAPublicKey)val;
                    privKey = null;
                } else {
                    throw newDSAError(getRuntime(), "Neither PUB key nor PRIV key:");
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
            return RubyString.newString(getRuntime(), pubKey.getEncoded());
        } else if(privKey != null && pubKey != null) {
            DSAParams params = privKey.getParams();
            ASN1EncodableVector v1 = new ASN1EncodableVector();
            v1.add(new DERInteger(0));
            v1.add(new DERInteger(params.getP()));
            v1.add(new DERInteger(params.getQ()));
            v1.add(new DERInteger(params.getG()));
            v1.add(new DERInteger(pubKey.getY()));
            v1.add(new DERInteger(privKey.getX()));
            return RubyString.newString(getRuntime(), new DERSequence(v1).getEncoded());
        } else {
            return RubyString.newString(getRuntime(), privKey.getEncoded());
        }
    }

    @JRubyMethod
    public IRubyObject to_text() throws Exception {
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject public_key() {
        PKeyDSA val = new PKeyDSA(getRuntime(),getMetaClass().getRealClass());
        val.privKey = null;
        val.pubKey = this.pubKey;
        return val;
    }

    @JRubyMethod(name={"export","to_pem","to_s"}, rest=true)
    public IRubyObject export(IRubyObject[] args) throws Exception {
        StringWriter w = new StringWriter();
        org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,0,2);
        char[] passwd = null;
        String algo = null;
        if(args.length > 0 && !args[0].isNil()) {
            algo = ((Cipher)args[0]).getAlgorithm();
            if(args.length > 1 && !args[1].isNil()) {
                passwd = args[1].toString().toCharArray();
            }
        }
        if(privKey != null) {
            PEMInputOutput.writeDSAPrivateKey(w,privKey,algo,passwd);
        } else {
            PEMInputOutput.writeDSAPublicKey(w,pubKey);
        }
        w.close();
        return getRuntime().newString(w.toString());
    }

    /* 
    private String getPadding(int padding) {
        if(padding < 1 || padding > 4) {
            throw new RaiseException(getRuntime(), (RubyClass)(((RubyModule)(getRuntime().getModule("OpenSSL").getConstant("PKey"))).getConstant("DSAError")), null, true);
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
    */      

    @JRubyMethod
    public IRubyObject syssign(IRubyObject arg) {
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject sysverify(IRubyObject arg, IRubyObject arg2) {
        return getRuntime().getNil();
    }
    
    @JRubyMethod(name="p")
    public synchronized IRubyObject get_p() {
        // FIXME: return only for public?
        DSAKey key;
        BigInteger param;
        if ((key = this.pubKey) != null || (key = this.privKey) != null) {
            if ((param = key.getParams().getP()) != null) {
                return BN.newBN(getRuntime(), param);
            }
        } else if (specValues != null) {
            if ((param = specValues[SPEC_P]) != null) {
                return BN.newBN(getRuntime(), param);
            }
        }
        return getRuntime().getNil();
    }
    
    @JRubyMethod(name="p=")
    public synchronized IRubyObject set_p(IRubyObject p) {
        return setKeySpecComponent(SPEC_P, p);
    }

    @JRubyMethod(name="q")
    public synchronized IRubyObject get_q() {
        // FIXME: return only for public?
        DSAKey key;
        BigInteger param;
        if ((key = this.pubKey) != null || (key = this.privKey) != null) {
            if ((param = key.getParams().getQ()) != null) {
                return BN.newBN(getRuntime(), param);
            }
        } else if (specValues != null) {
            if ((param = specValues[SPEC_Q]) != null) {
                return BN.newBN(getRuntime(), param);
            }
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="q=")
    public synchronized IRubyObject set_q(IRubyObject q) {
        return setKeySpecComponent(SPEC_Q, q);
    }

    @JRubyMethod(name="g")
    public synchronized IRubyObject get_g() {
        // FIXME: return only for public?
        DSAKey key;
        BigInteger param;
        if ((key = this.pubKey) != null || (key = this.privKey) != null) {
            if ((param = key.getParams().getG()) != null) {
                return BN.newBN(getRuntime(), param);
            }
        } else if (specValues != null) {
            if ((param = specValues[SPEC_G]) != null) {
                return BN.newBN(getRuntime(), param);
            }
        }
        return getRuntime().getNil();
    }
    
    @JRubyMethod(name="g=")
    public synchronized IRubyObject set_g(IRubyObject g) {
        return setKeySpecComponent(SPEC_G, g);
    }

    @JRubyMethod(name="pub_key")
    public synchronized IRubyObject get_pub_key() {
        DSAPublicKey key;
        BigInteger param;
        if ((key = this.pubKey) != null) {
            return BN.newBN(getRuntime(), key.getY());
        } else if (specValues != null) {
            if ((param = specValues[SPEC_Y]) != null) {
                return BN.newBN(getRuntime(), param);
            }
        }
        return getRuntime().getNil();
    }
    
    @JRubyMethod(name="pub_key=")
    public synchronized IRubyObject set_pub_key(IRubyObject pub_key) {
        return setKeySpecComponent(SPEC_Y, pub_key);
    }

    private IRubyObject setKeySpecComponent(int index, IRubyObject value) {
        BigInteger[] vals;
        // illegal to set if we already have a key for this component
        // FIXME: allow changes after keys are created? MRI doesn't prevent it...
        if (this.pubKey != null || this.privKey != null ||
                (vals = this.specValues) != null && vals[index] != null) {
            throw newDSAError(getRuntime(), "illegal modification");
        }
        // get the BigInteger value
        BigInteger bival = BN.getBigInteger(value);
        
        if (vals != null) {
            // we already have some vals stored, store this one, too
            vals[index] = bival;
            // check to see if we have all values yet
            for (int i = vals.length; --i >= 0; ) {
                if (vals[i] == null) {
                    // still missing components, return
                    return value;
                }
            }
            // we now have all components. create the key.
            DSAPublicKeySpec spec = new DSAPublicKeySpec(vals[SPEC_Y], vals[SPEC_P], vals[SPEC_Q], vals[SPEC_G]);
            try {
                this.pubKey = (DSAPublicKey)KeyFactory.getInstance("DSA").generatePublic(spec);
            } catch (InvalidKeySpecException e) {
                throw newDSAError(getRuntime(), "invalid keyspec");
            } catch (NoSuchAlgorithmException e) {
                throw newDSAError(getRuntime(), "unsupported key algorithm (DSA)");
            }
            // clear out the specValues
            this.specValues = null;

        } else {

            // first value received, save
            this.specValues = new BigInteger[4];
            this.specValues[index] = bival;
        }
        return value;
    }

}// PKeyDSA
