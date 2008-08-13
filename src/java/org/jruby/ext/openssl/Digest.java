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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.runtime.Block;
import org.jruby.anno.JRubyMethod;
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

        cDigest.defineAnnotatedMethods(Digest.class);
    }

    private static MessageDigest getDigest(final String name, final IRubyObject recv) {
        return (MessageDigest) OpenSSLReal.getWithBCProvider(new Callable() {
            public Object call() {
                try {
                    return MessageDigest.getInstance(transformDigest(name));
                } catch (NoSuchAlgorithmException e) {
                    throw recv.getRuntime().newNotImplementedError("Unsupported digest algorithm (" + name + ")");
                }
            }
        });
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

    @JRubyMethod(name="digest", meta=true)
    public static IRubyObject s_digest(IRubyObject recv, IRubyObject str, IRubyObject data) {
        String name = str.toString();
        MessageDigest md = getDigest(name, recv);
        return RubyString.newString(recv.getRuntime(), md.digest(data.convertToString().getBytes()));
    }

    @JRubyMethod(name="hexdigest", meta=true)
    public static IRubyObject s_hexdigest(IRubyObject recv, IRubyObject str, IRubyObject data) {
        String name = str.toString();
        MessageDigest md = getDigest(name, recv);
        return RubyString.newString(recv.getRuntime(), ByteList.plain(Utils.toHex(md.digest(data.convertToString().getBytes()))));
    }

    public Digest(Ruby runtime, RubyClass type) {
        super(runtime,type);
        data = new StringBuffer();

        if(!(type.toString().equals("OpenSSL::Digest::Digest"))) {
            name = type.toString();
            md = getDigest(name, this);
        }
    }

    private MessageDigest md;
    private StringBuffer data;
    private String name;

    public String getRealName() {
        return transformDigest(name);
    }

    public String getName() {
        return name;
    }

    @JRubyMethod(rest=true)
    public IRubyObject initialize(IRubyObject[] args) {
        IRubyObject type;
        IRubyObject data = getRuntime().getNil();
        if(org.jruby.runtime.Arity.checkArgumentCount(getRuntime(),args,1,2) == 2) {
            data = args[1];
        }
        type = args[0];

        name = type.toString();
        md = getDigest(name, this);
        if(!data.isNil()) {
            update(data);
        }
        return this;
    }

    @JRubyMethod
    public IRubyObject initialize_copy(IRubyObject obj) {
        if(this == obj) {
            return this;
        }
        checkFrozen();
        data = new StringBuffer(((Digest)obj).data.toString());
        name = ((Digest)obj).md.getAlgorithm();
        md = getDigest(name, this);

        return this;
    }

    @JRubyMethod(name={"update","<<"})
    public IRubyObject update(IRubyObject obj) {
        data.append(obj);
        md.update(obj.convertToString().getBytes());
        return this;
    }

    @JRubyMethod
    public IRubyObject reset() {
        md.reset();
        data = new StringBuffer();
        return this;
    }

    @JRubyMethod
    public IRubyObject digest() {
        md.reset();
        return RubyString.newString(getRuntime(), md.digest(ByteList.plain(data)));
    }

    @JRubyMethod
    public IRubyObject name() {
        return getRuntime().newString(name);
    }

    @JRubyMethod
    public IRubyObject size() {
        return getRuntime().newFixnum(md.getDigestLength());
    }

    @JRubyMethod(name={"hexdigest","inspect","to_s"})
    public IRubyObject hexdigest() {
        md.reset();
        return RubyString.newString(getRuntime(), ByteList.plain(Utils.toHex(md.digest(ByteList.plain(data)))));
    }

    @JRubyMethod(name="==")
    public IRubyObject eq(IRubyObject oth) {
        boolean ret = this == oth;
        if(!ret && oth instanceof Digest) {
            Digest b = (Digest)oth;
            ret = this.md.getAlgorithm().equals(b.md.getAlgorithm()) &&
                this.digest().equals(b.digest());
        }

        return ret ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    String getAlgorithm() {
        return this.md.getAlgorithm();
    }
}

