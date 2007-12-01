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


import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.runtime.Block;
import org.jruby.runtime.CallbackFactory;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Digest extends RubyObject {
    private static ObjectAllocator DIGEST_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new Digest(runtime, klass);
        }
    };
    
    public static void createDigest(Ruby runtime, RubyModule ossl) {
        RubyModule mDigest = ossl.defineModuleUnder("Digest");
        RubyClass cDigest = mDigest.defineClassUnder("Digest",runtime.getObject(),DIGEST_ALLOCATOR);
        RubyClass openSSLError = ossl.getClass("OpenSSLError");
        mDigest.defineClassUnder("DigestError",openSSLError,openSSLError.getAllocator());

        CallbackFactory digestcb = runtime.callbackFactory(Digest.class);

        cDigest.getMetaClass().defineFastMethod("digest",digestcb.getFastSingletonMethod("s_digest",IRubyObject.class,IRubyObject.class));
        cDigest.getMetaClass().defineFastMethod("hexdigest",digestcb.getFastSingletonMethod("s_hexdigest",IRubyObject.class,IRubyObject.class));
        cDigest.defineMethod("initialize",digestcb.getOptMethod("initialize"));
        cDigest.defineFastMethod("initialize_copy",digestcb.getFastMethod("initialize_copy",IRubyObject.class));
        cDigest.defineFastMethod("update",digestcb.getFastMethod("update",IRubyObject.class));
        cDigest.defineFastMethod("<<",digestcb.getFastMethod("update",IRubyObject.class));
        cDigest.defineFastMethod("digest",digestcb.getFastMethod("digest"));
        cDigest.defineFastMethod("hexdigest",digestcb.getFastMethod("hexdigest"));
        cDigest.defineFastMethod("inspect",digestcb.getFastMethod("hexdigest"));
        cDigest.defineFastMethod("to_s",digestcb.getFastMethod("hexdigest"));
        cDigest.defineFastMethod("==",digestcb.getFastMethod("eq",IRubyObject.class));
        cDigest.defineFastMethod("reset",digestcb.getFastMethod("reset"));
        cDigest.defineFastMethod("name",digestcb.getFastMethod("name"));
        cDigest.defineFastMethod("size",digestcb.getFastMethod("size"));
    }

    private static String transformDigest(String inp) {
        String[] sp = inp.split("::");
        if(sp.length > 1) { // We only want Digest names from the last part of class name
            inp = sp[sp.length-1];
        }

        if("DSS".equalsIgnoreCase(inp)) {
            return "SHA";
        } else if("DSS1".equalsIgnoreCase(inp)) {
            return "SHA1";
        }
        return inp;
    }
    
    public static org.bouncycastle.crypto.Digest getDigest(Ruby runtime, String name) {
        if (name.equals("MD5")) {
            return new MD5Digest();
        } else if (name.equals("SHA")) {
            return new SHA1Digest();
        } else if (name.equals("SHA1")) {
            return new SHA1Digest();
        } else if (name.equals("SHA224")) {
            return new SHA224Digest();
        } else if (name.equals("SHA256")) {
            return new SHA256Digest();
        } else if (name.equals("SHA384")) {
            return new SHA384Digest();
        } else if (name.equals("SHA512")) {
            return new SHA512Digest();
        } else {
            throw runtime.newNotImplementedError("Unsupported digest algorithm (" + name + ")");
        }
    }

    public static IRubyObject s_digest(IRubyObject recv, IRubyObject str, IRubyObject data) {
        String name = str.toString();

        org.bouncycastle.crypto.Digest md = getDigest(recv.getRuntime(), name);
        byte[] bytes = data.convertToString().getBytes();
        
        md.update(bytes, 0, bytes.length);
        byte[] digest = new byte[md.getDigestSize()];
        md.doFinal(digest, 0);
        return RubyString.newString(recv.getRuntime(), new ByteList(digest));
    }

    public static IRubyObject s_hexdigest(IRubyObject recv, IRubyObject str, IRubyObject data) {
        String name = str.toString();

        org.bouncycastle.crypto.Digest md = getDigest(recv.getRuntime(), transformDigest(name));
        byte[] bytes = data.convertToString().getBytes();
        
        md.update(bytes, 0, bytes.length);
        byte[] digest = new byte[md.getDigestSize()];
        md.doFinal(digest, 0);
        return RubyString.newString(recv.getRuntime(), ByteList.plain(Utils.toHex(digest)));
    }

    public Digest(Ruby runtime, RubyClass type) {
        super(runtime,type);
        data = new StringBuffer();

        if(!(type.toString().equals("OpenSSL::Digest::Digest"))) {
            name = type.toString();
            md = getDigest(runtime, transformDigest(type.toString()));
        }
    }

    private org.bouncycastle.crypto.Digest md;
    private StringBuffer data;
    private String name;

    public IRubyObject initialize(IRubyObject[] args, Block unusedBlock) {
        IRubyObject type;
        IRubyObject data = getRuntime().getNil();
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,1,2) == 2) {
            data = args[1];
        }
        type = args[0];

        name = type.toString();
        md = getDigest(getRuntime(), transformDigest(name));
            
        if(!data.isNil()) {
            update(data);
        }
        return this;
    }

    public IRubyObject initialize_copy(IRubyObject obj) {
        if(this == obj) {
            return this;
        }
        checkFrozen();
        data = new StringBuffer(((Digest)obj).data.toString());
        name = ((Digest)obj).md.getAlgorithmName();
        md = getDigest(getRuntime(), transformDigest(name));

        return this;
    }

    public IRubyObject update(IRubyObject obj) {
        data.append(obj);
        byte[] bytes = obj.convertToString().getBytes();
        md.update(bytes, 0, bytes.length);
        return this;
    }

    public IRubyObject reset() {
        md.reset();
        data = new StringBuffer();
        return this;
    }

    public IRubyObject digest() {
        md.reset();
        byte[] bytes = ByteList.plain(data);
        md.update(bytes, 0, bytes.length);
        byte[] digest = new byte[md.getDigestSize()];
        md.doFinal(digest, 0);
        return RubyString.newString(getRuntime(), digest);
    }

    public IRubyObject name() {
        return getRuntime().newString(name);
    }

    public IRubyObject size() {
        return getRuntime().newFixnum(md.getDigestSize());
    }

    public IRubyObject hexdigest() {
        md.reset();
        byte[] bytes = ByteList.plain(data);
        md.update(bytes, 0, bytes.length);
        byte[] digest = new byte[md.getDigestSize()];
        md.doFinal(digest, 0);
        return RubyString.newString(getRuntime(), ByteList.plain(Utils.toHex(digest)));
    }

    public IRubyObject eq(IRubyObject oth) {
        boolean ret = this == oth;
        if(!ret && oth instanceof Digest) {
            Digest b = (Digest)oth;
            ret = this.md.getAlgorithmName().equals(b.md.getAlgorithmName()) &&
                this.digest().equals(b.digest());
        }

        return ret ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    String getAlgorithm() {
        return this.md.getAlgorithmName().replace("-", "");
    }
}

