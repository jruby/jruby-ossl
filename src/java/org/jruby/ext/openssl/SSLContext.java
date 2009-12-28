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



import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLEngine;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.common.IRubyWarnings.ID;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.Certificate;
import org.jruby.ext.openssl.x509store.Name;
import org.jruby.ext.openssl.x509store.Store;
import org.jruby.ext.openssl.x509store.StoreContext;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.ext.openssl.x509store.X509Object;
import org.jruby.ext.openssl.x509store.X509Utils;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SSLContext extends RubyObject {
    private final static String[] ctx_attrs = {
    "cert", "key", "client_ca", "ca_file", "ca_path",
    "timeout", "verify_mode", "verify_depth",
    "verify_callback", "options", "cert_store", "extra_chain_cert",
    "client_cert_cb", "tmp_dh_callback", "session_id_context"};

    // Mapping table for OpenSSL's SSL_METHOD -> JSSE's SSLContext algorithm.
    private final static Map<String, String> SSL_VERSION_OSSL2JSSE;
    // Mapping table for JSEE's enabled protocols for the algorithm.
    private final static Map<String, String[]> ENABLED_PROTOCOLS;
    
    static {
        SSL_VERSION_OSSL2JSSE = new HashMap<String, String>();
        ENABLED_PROTOCOLS = new HashMap<String, String[]>();

        SSL_VERSION_OSSL2JSSE.put("TLSv1", "TLSv1");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_server", "TLSv1");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_client", "TLSv1");
        ENABLED_PROTOCOLS.put("TLSv1", new String[] { "TLSv1" });

        SSL_VERSION_OSSL2JSSE.put("SSLv2", "SSLv2");
        SSL_VERSION_OSSL2JSSE.put("SSLv2_server", "SSLv2");
        SSL_VERSION_OSSL2JSSE.put("SSLv2_client", "SSLv2");
        ENABLED_PROTOCOLS.put("SSLv2", new String[] { "SSLv2" });

        SSL_VERSION_OSSL2JSSE.put("SSLv3", "SSLv3");
        SSL_VERSION_OSSL2JSSE.put("SSLv3_server", "SSLv3");
        SSL_VERSION_OSSL2JSSE.put("SSLv3_client", "SSLv3");
        ENABLED_PROTOCOLS.put("SSLv3", new String[] { "SSLv3" });

        SSL_VERSION_OSSL2JSSE.put("SSLv23", "SSL");
        SSL_VERSION_OSSL2JSSE.put("SSLv23_server", "SSL");
        SSL_VERSION_OSSL2JSSE.put("SSLv23_client", "SSL");
        ENABLED_PROTOCOLS.put("SSL", new String[] { "SSLv2", "SSLv3", "TLSv1" });

        // Followings(TLS, TLSv1.1) are JSSE only methods at present. Let's allow user to use it.
        
        SSL_VERSION_OSSL2JSSE.put("TLS", "TLS");
        ENABLED_PROTOCOLS.put("TLS", new String[] { "TLSv1", "TLSv1.1" });

        SSL_VERSION_OSSL2JSSE.put("TLSv1.1", "TLSv1.1");
        ENABLED_PROTOCOLS.put("TLSv1.1", new String[] { "TLSv1.1" });
    }

    private static ObjectAllocator SSLCONTEXT_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new SSLContext(runtime, klass);
        }
    };
    
    public static void createSSLContext(Ruby runtime, RubyModule mSSL) {
        RubyClass cSSLContext = mSSL.defineClassUnder("SSLContext",runtime.getObject(),SSLCONTEXT_ALLOCATOR);
        for(int i=0;i<ctx_attrs.length;i++) {
            cSSLContext.attr_accessor(runtime.getCurrentContext(),new IRubyObject[]{runtime.newSymbol(ctx_attrs[i])});
        }

        cSSLContext.defineAnnotatedMethods(SSLContext.class);
    }

    public SSLContext(Ruby runtime, RubyClass type) {
        super(runtime,type);
        cSSLError = (RubyClass)((RubyModule)getRuntime().getModule("OpenSSL").getConstant("SSL")).getConstant("SSLError");
    }

    private RubyClass cSSLError;
    private String ciphers = CipherStrings.SSL_DEFAULT_CIPHER_LIST;
    private String protocol = "SSL"; // SSLv23 in OpenSSL by default
    private boolean protocolForServer = true;
    private boolean protocolForClient = true;
    private PKey t_key = null;
    private X509Cert t_cert = null;
    private java.security.cert.X509Certificate peer_cert;
    /* TODO: should move to SSLSession after implemented */
    private int verifyResult = 1; /* avoid 0 (= X509_V_OK) just in case */

    public void setPeer(java.security.cert.X509Certificate p) {
        this.peer_cert = p;
    }

    public java.security.cert.X509Certificate getPeer() {
        return this.peer_cert;
    }

    private void initFromCallback(IRubyObject cb) {
        IRubyObject out = cb.callMethod(getRuntime().getCurrentContext(),"call",this);
        t_cert = (X509Cert)(((RubyArray)out).getList().get(0));
        t_key = (PKey)(((RubyArray)out).getList().get(1));
    }

    PKey getCallbackKey() {
        IRubyObject cb = callMethod(getRuntime().getCurrentContext(),"client_cert_cb");
        if(t_key == null && !cb.isNil()) {
            initFromCallback(cb);
        }
        return t_key;
    }

    X509Cert getCallbackCert() {
        IRubyObject cb = callMethod(getRuntime().getCurrentContext(),"client_cert_cb");
        if(t_cert == null && !cb.isNil()) {
            initFromCallback(cb);
        }
        return t_cert;
    }

    @JRubyMethod(rest=true)
    public IRubyObject initialize(IRubyObject[] args) {
        return this;
    }

    @JRubyMethod
    public IRubyObject setup() {
        if (isFrozen()) {
            return getRuntime().getNil();
        }
        // should do good things for performance: SSLContext, KM and TM setup and cache.
        this.freeze(getRuntime().getCurrentContext());
        return getRuntime().getTrue();
    }

    @JRubyMethod
    public IRubyObject ciphers() {
        List<IRubyObject> list = new ArrayList<IRubyObject>();
        Ruby rt = getRuntime();
        try {
            List<CipherStrings.Def> ciphs = CipherStrings.getMatchingCiphers(ciphers, createSSLEngine().getSupportedCipherSuites());
            for (CipherStrings.Def def : ciphs) {
                RubyArray ele = getRuntime().newArray(4);
                ele.set(0, rt.newString(def.name));
                ele.set(1, rt.newString(sslVersionString(def.algorithms)));
                ele.set(2, rt.newFixnum(def.strength_bits));
                ele.set(3, rt.newFixnum(def.alg_bits));
                list.add(ele);
            }
        } catch (NoSuchAlgorithmException nsae) {
            // ignore
        } catch (KeyManagementException kme) {
            // ignore
        }
        return rt.newArray(list);
    }

    @JRubyMethod(name = "ciphers=")
    public IRubyObject set_ciphers(IRubyObject val) {
        if (val.isNil()) {
            ciphers = CipherStrings.SSL_DEFAULT_CIPHER_LIST;
        } else if (val instanceof RubyArray) {
            StringBuilder builder = new StringBuilder();
            String sep = "";
            for (Iterator iter = ((RubyArray) val).getList().iterator(); iter.hasNext();) {
                builder.append(sep).append(iter.next().toString());
                sep = ":";
            }
            ciphers = builder.toString();
        } else {
            ciphers = val.toString();
        }
        RubyArray ary = (RubyArray)ciphers();
        if (ary.size() == 0) {
            throw new RaiseException(getRuntime(), cSSLError, "no cipher match", false);
        }
        return val;
    }

    @JRubyMethod(name = "ssl_version=")
    public IRubyObject set_ssl_version(IRubyObject val) {
        RubyString str = val.convertToString();
        String given = str.toString();
        String mapped = SSL_VERSION_OSSL2JSSE.get(given);
        if (mapped == null) {
            throw new RaiseException(getRuntime(), cSSLError, String.format("unknown SSL method `%s'.", given), false);
        }
        protocol = mapped;
        protocolForServer = protocolForClient = true;
        if (given.endsWith("_client")) {
            protocolForServer = false;
        }
        if (given.endsWith("_server")) {
            protocolForClient = false;
        }
        return str;
    }

    boolean isProtocolForServer() {
        return protocolForServer;
    }

    boolean isProtocolForClient() {
        return protocolForClient;
    }

    // should keep SSLContext as a member for introducin SSLSession. later...
    SSLEngine createSSLEngine() throws NoSuchAlgorithmException, KeyManagementException {
        SSLEngine engine = createSSLContext().createSSLEngine();
        engine.setEnabledCipherSuites(getCipherSuites(engine));
        engine.setEnabledProtocols(getEnabledProtocols(engine));
        return engine;
    }

    // should keep SSLContext as a member for introducin SSLSession. later...
    SSLEngine createSSLEngine(String peerHost, int peerPort) throws NoSuchAlgorithmException, KeyManagementException {
        SSLEngine engine = createSSLContext().createSSLEngine(peerHost, peerPort);
        engine.setEnabledCipherSuites(getCipherSuites(engine));
        engine.setEnabledProtocols(getEnabledProtocols(engine));
        return engine;
    }

    private javax.net.ssl.SSLContext createSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance(protocol);
        ctx.init(new javax.net.ssl.KeyManager[]{getKM()}, new javax.net.ssl.TrustManager[]{getTM()}, null);
        return ctx;
    }

    private String[] getCipherSuites(SSLEngine engine) {
        List<CipherStrings.Def> ciphs = CipherStrings.getMatchingCiphers(ciphers, engine.getSupportedCipherSuites());
        String[] result = new String[ciphs.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = ciphs.get(i).cipherSuite;
        }
        return result;
    }

    private String[] getEnabledProtocols(SSLEngine engine) {
        List<String> candidates = new ArrayList<String>();
        if (ENABLED_PROTOCOLS.get(protocol) != null) {
            for (String enabled : ENABLED_PROTOCOLS.get(protocol)) {
                for (String allowed : engine.getEnabledProtocols()) {
                    if (allowed.equals(enabled)) {
                        candidates.add(allowed);
                    }
                }
            }
        }
        return candidates.toArray(new String[candidates.size()]);
    }

    private String sslVersionString(long bits) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        if ((bits & CipherStrings.SSL_SSLV3) != 0) {
            if (!first) {
                sb.append("/");
            }
            first = false;
            sb.append("TLSv1/SSLv3");
        }
        if ((bits & CipherStrings.SSL_SSLV2) != 0) {
            if (!first) {
                sb.append("/");
            }
            first = false;
            sb.append("SSLv2");
        }
        return sb.toString();
    }

    int getLastVerifyResult() {
        return verifyResult;
    }

    void setLastVerifyResult(int verifyResult) {
        this.verifyResult = verifyResult;
    }

    RubyFixnum getVerifyMode() {
        IRubyObject value = getInstanceVariable("@verify_mode");
        if (value != null && !value.isNil()) {
            return (RubyFixnum) value;
        } else {
            return null;
        }
    }

    PKey getPKey() {
        IRubyObject value = getInstanceVariable("@key");
        if (value != null && !value.isNil()) {
            return (PKey) value;
        } else {
            return getCallbackKey();
        }
    }

    X509Cert getCert() {
        IRubyObject value = getInstanceVariable("@cert");
        if (value != null && !value.isNil()) {
            return (X509Cert) value;
        } else {
            return getCallbackCert();
        }
    }

    StoreContext createStoreContext() {
        StoreContext ctx = new StoreContext();
        X509Store certStore = getCertStore();
        Store store = null;
        if (certStore != null) {
            store = certStore.getStore();
        }
        if (ctx.init(store, null, null) == 0) {
            return null;
        }
        String ca_file = getCaFile();
        String ca_path = getCaPath();
        if (ca_file != null || ca_path != null) {
            if (ctx.loadVerifyLocations(ca_file, ca_path) == 0) {
                getRuntime().getWarnings().warn(ID.MISCELLANEOUS, "can't set verify locations");
            }
        }
        IRubyObject cb = getVerifyCallback();
        if (cb != null) {
            ctx.setVerifyCallback(X509Store.ossl_verify_cb);
            ctx.setExtraData(1, cb);
        }
        return ctx;
    }

    private X509Store getCertStore() {
        IRubyObject value = getInstanceVariable("@cert_store");
        if (value != null && !value.isNil()) {
            return (X509Store) value;
        } else {
            return null;
        }
    }

    private String getCaFile() {
        IRubyObject value = getInstanceVariable("@ca_file");
        if (value != null && !value.isNil()) {
            return value.convertToString().toString();
        } else {
            return null;
        }
    }

    private String getCaPath() {
        IRubyObject value = getInstanceVariable("@ca_path");
        if (value != null && !value.isNil()) {
            return value.convertToString().toString();
        } else {
            return null;
        }
    }

    private IRubyObject getVerifyCallback() {
        IRubyObject value = getInstanceVariable("@verify_callback");
        if (value != null && !value.isNil()) {
            return value;
        } else {
            return null;
        }
    }

    private KM getKM() {
        return new KM(this);
    }

    private TM getTM() {
        return new TM(this);
    }

    private static class KM extends javax.net.ssl.X509ExtendedKeyManager {

        private final SSLContext ctt;
        
        public KM(SSLContext ctt) {
            super();
            this.ctt = ctt;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            PKey k = ctt.getPKey();
            if (k == null) {
                return null;
            }
            for (int i = 0; i < keyType.length; i++) {
                if (keyType[i].equalsIgnoreCase(k.getAlgorithm())) {
                    return keyType[i];
                }
            }
            return null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            PKey k = ctt.getPKey();
            if (k == null) {
                return null;
            }
            if (keyType.equalsIgnoreCase(k.getAlgorithm())) {
                return keyType;
            }
            return null;
        }

        public String chooseClientAlias(String[] keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            return null;
        }

        public String chooseServerAlias(String keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            return null;
        }

        // c: ssl3_output_cert_chain
        public java.security.cert.X509Certificate[] getCertificateChain(String alias) {
            X509Cert c = ctt.getCert();
            if (c == null) {
                return null;
            }
            StoreContext ctx = ctt.createStoreContext();
            X509AuxCertificate x = c.getAuxCert();
            ArrayList<java.security.cert.X509Certificate> chain = new ArrayList<java.security.cert.X509Certificate>();
            while (true) {
                chain.add(x);
                if (x.getIssuerDN().equals(x.getSubjectDN())) {
                    break;
                }
                try {
                    Name xn = new Name(c.getAuxCert().getIssuerX500Principal());
                    X509Object[] s_obj = new X509Object[1];
                    if (ctx.getBySubject(X509Utils.X509_LU_X509, xn, s_obj) <= 0) {
                        break;
                    }
                    x = ((Certificate) s_obj[0]).x509;
                } catch (Exception e) {
                    break;
                }
            }
            return chain.toArray(new java.security.cert.X509Certificate[0]);
        }

        public String[] getClientAliases(String keyType, java.security.Principal[] issuers) {
            return null;
        }

        public java.security.PrivateKey getPrivateKey(String alias) {
            PKey k = ctt.getPKey();
            if (k == null) {
                return null;
            }
            return k.getPrivateKey();
        }

        public String[] getServerAliases(String keyType, java.security.Principal[] issuers) {
            return null;
        }
    }

    private static class TM implements javax.net.ssl.X509TrustManager {

        private SSLContext ctt;

        public TM(SSLContext ctt) {
            this.ctt = ctt;
        }

        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            checkTrusted("ssl_client", chain);
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            checkTrusted("ssl_server", chain);
        }

        // TODO: check CRuby compatibility
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }

        // c: ssl_verify_cert_chain
        private void checkTrusted(String purpose, X509Certificate[] chain) throws CertificateException {
            if (chain != null && chain.length > 0) {
                ctt.setPeer(chain[0]);
            }
            if (ctt.getVerifyMode() == null) {
                return;
            }
            int verify_mode = RubyNumeric.fix2int(ctt.getVerifyMode());
            if (chain != null && chain.length > 0) {
                ctt.setPeer(chain[0]);
                if ((verify_mode & 0x1) != 0) {
                    // verify_peer
                    StoreContext ctx = ctt.createStoreContext();
                    if (ctx == null) {
                        throw new CertificateException("couldn't initialize store");
                    }
                    ctx.setCertificate(chain[0]);
                    ctx.setChain(chain);
                    ctx.setDefault(purpose);
                    verifyChain(ctx);
                }
            } else {
                if ((verify_mode & 0x2) != 0) {
                    // fail if no peer cert
                    throw new CertificateException("no peer certificate");
                }
            }
        }

        private void verifyChain(StoreContext ctx) throws CertificateException {
            try {
                int ok = ctx.verifyCertificate();
                ctt.setLastVerifyResult(ctx.error);
                if (ok == 0) {
                    throw new CertificateException("certificate verify failed");
                }
            } catch (Exception e) {
                throw new CertificateException("certificate verify failed", e);
            }
        }
    }
}// SSLContext
