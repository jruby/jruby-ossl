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
 * Copyright (C) 2006 Ola Bini <ola@ologix.com>
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

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class OpenSSLReal {
    public static java.security.Provider PROVIDER;

    static {
        try {
            PROVIDER = (java.security.Provider) 
                Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
        } catch (Exception exception) {
            // no bouncy castle available
        }
    }

    public static void doWithBCProvider(final Runnable toRun) {
        getWithBCProvider(new Callable() {

            public Object call() {
                toRun.run();
                return null;
            }
        });
    }

    public static Object getWithBCProvider(Callable toRun) {
        if (PROVIDER != null) {
            synchronized (java.security.Security.class) {
                try {
                    java.security.Security.addProvider(PROVIDER);
                    return toRun.call();
                } finally {
                    java.security.Security.removeProvider("BC");
                }
            }
        } else {
            return toRun.call();
        }
    }

    public static void createOpenSSL(Ruby runtime) {
        RubyModule ossl = runtime.getOrCreateModule("OpenSSL");
        RubyClass standardError = runtime.getClass("StandardError");
        ossl.defineClassUnder("OpenSSLError", standardError, standardError.getAllocator());

        if (PROVIDER != null) {
            ASN1.createASN1(runtime, ossl);
            PKey.createPKey(runtime, ossl);
            X509.createX509(runtime, ossl);
            NetscapeSPKI.createNetscapeSPKI(runtime, ossl);
            PKCS7.createPKCS7(runtime, ossl);
        } else {
            runtime.getLoadService().require("openssl/dummy");
        }

        BN.createBN(runtime, ossl);
        Digest.createDigest(runtime, ossl);
        Cipher.createCipher(runtime, ossl);
        Random.createRandom(runtime, ossl);
        HMAC.createHMAC(runtime, ossl);
        Config.createConfig(runtime, ossl);

        try {
            SSL.createSSL(runtime, ossl);
        } catch (Error err) {
            runtime.getLoadService().require("openssl/dummyssl");
        }

        ossl.setConstant("VERSION", runtime.newString("1.0.0"));
        ossl.setConstant("OPENSSL_VERSION", runtime.newString("OpenSSL 0.9.8b 04 May 2006 (JRuby-OpenSSL fake)"));

        try {
            java.security.MessageDigest.getInstance("SHA224", PROVIDER);
            ossl.setConstant("OPENSSL_VERSION_NUMBER", runtime.newFixnum(9469999));
        } catch (Exception e) {
            ossl.setConstant("OPENSSL_VERSION_NUMBER", runtime.newFixnum(9469952));
        }
    }
}// OpenSSLReal

