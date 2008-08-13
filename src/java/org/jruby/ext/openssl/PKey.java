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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public abstract class PKey extends RubyObject {
    public static void createPKey(Ruby runtime, RubyModule ossl) {
        RubyModule mPKey = ossl.defineModuleUnder("PKey");
        // PKey is abstract
        RubyClass cPKey = mPKey.defineClassUnder("PKey",runtime.getObject(),ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);
        RubyClass openSSLError = ossl.getClass("OpenSSLError");
        mPKey.defineClassUnder("PKeyError",openSSLError,openSSLError.getAllocator());

        cPKey.defineAnnotatedMethods(PKey.class);

        PKeyRSA.createPKeyRSA(runtime,mPKey);
        PKeyDSA.createPKeyDSA(runtime,mPKey);
        PKeyDH.createPKeyDH(runtime, mPKey, cPKey);
    }

    public static RaiseException newPKeyError(Ruby runtime, String message) {
        return new RaiseException(runtime, ((RubyModule)runtime.getModule("OpenSSL").getConstantAt("PKey")).getClass("PKeyError"), message, true);
    }

    public PKey(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    @JRubyMethod
    public IRubyObject initialize() {
        return this;
    }

    PublicKey getPublicKey() {
        return null;
    }

    PrivateKey getPrivateKey() {
        return null;
    }

    String getAlgorithm() {
        return "NONE";
    }

    // FIXME: any compelling reason for abstract method here?
    public abstract IRubyObject to_der() throws Exception;

    @JRubyMethod
    public IRubyObject sign(IRubyObject digest, IRubyObject data) throws Exception {
        if(!this.callMethod(getRuntime().getCurrentContext(),"private?").isTrue()) {
            throw getRuntime().newArgumentError("Private key is needed.");
        }
        Signature sig = Signature.getInstance(((Digest)digest).getAlgorithm() + "WITH" + getAlgorithm(),OpenSSLReal.PROVIDER);
        sig.initSign(getPrivateKey());
        byte[] inp = data.convertToString().getBytes();
        sig.update(inp);
        byte[] sigge = sig.sign();
        return RubyString.newString(getRuntime(), sigge);
        /*
    GetPKey(self, pkey);
    EVP_SignInit(&ctx, GetDigestPtr(digest));
    StringValue(data);
    EVP_SignUpdate(&ctx, RSTRING(data)->ptr, RSTRING(data)->len);
    str = rb_str_new(0, EVP_PKEY_size(pkey)+16);
    if (!EVP_SignFinal(&ctx, RSTRING(str)->ptr, &buf_len, pkey))
    ossl_raise(ePKeyError, NULL);
    assert(buf_len <= RSTRING(str)->len);
    RSTRING(str)->len = buf_len;
    RSTRING(str)->ptr[buf_len] = 0;

    return str;
         */
    }

    @JRubyMethod
    public IRubyObject verify(IRubyObject digest, IRubyObject sig, IRubyObject data) {
        if (!(digest instanceof Digest)) {
            throw newPKeyError(getRuntime(), "invalid digest");
        }
        if (!(sig instanceof RubyString)) {
            throw newPKeyError(getRuntime(), "invalid signature");
        }
        if (!(data instanceof RubyString)) {
            throw newPKeyError(getRuntime(), "invalid data");
        }
        byte[] sigBytes = ((RubyString)sig).getBytes();
        byte[] dataBytes = ((RubyString)data).getBytes();
        String algorithm = ((Digest)digest).getRealName() + "with" + getAlgorithm();
        boolean valid;
        try {
            // note: not specifying "BC" provider here, as that would fail if
            // BC wasn't plugged in (as it would not be for, say, Net::SSH)
            Signature signature = OpenSSLReal.PROVIDER == null ? 
                Signature.getInstance(algorithm) :
                Signature.getInstance(algorithm, OpenSSLReal.PROVIDER);
            signature.initVerify(getPublicKey());
            signature.update(dataBytes);
            valid = signature.verify(sigBytes);
        } catch (NoSuchAlgorithmException e) {
            throw newPKeyError(getRuntime(), "unsupported algorithm: " + algorithm);
        } catch (SignatureException e) {
            throw newPKeyError(getRuntime(), "invalid signature");
        } catch (InvalidKeyException e) {
            throw newPKeyError(getRuntime(), "invalid key");
        }
        return getRuntime().newBoolean(valid);
    }
}// PKey
