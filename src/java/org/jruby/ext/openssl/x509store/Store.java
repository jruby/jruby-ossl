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
package org.jruby.ext.openssl.x509store;

import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.X509TrustManager;

/**
 * c: X509_STORE
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Store implements X509TrustManager {
    public int cache;
    public List<X509Object> objs;
    public List<Lookup> certificateMethods;
    public VerifyParameter param;

    public Function1 verify;
    public Function2 verifyCallback;
    public Function3 getIssuer;
    public Function3 checkIssued;
    public Function1 checkRevocation;
    public Function3 getCRL;
    public Function2 checkCRL;
    public Function3 certificateCRL;
    public Function1 cleanup;

    public List<Object> extraData;
    public int references;

    /**
     * c: X509_STORE_new
     */
    public Store() {
        objs = new ArrayList<X509Object>();
        cache = 1;
        certificateMethods = new ArrayList<Lookup>();

        verify = Function1.EMPTY;
        verifyCallback = Function2.EMPTY;

        param = new VerifyParameter();
        
        getIssuer = Function3.EMPTY;
        checkIssued = Function3.EMPTY;
        checkRevocation = Function1.EMPTY;
        getCRL = Function3.EMPTY;
        checkCRL = Function2.EMPTY;
        certificateCRL = Function3.EMPTY;
        cleanup = Function1.EMPTY;

        references = 1;
        extraData = new ArrayList<Object>();
        this.extraData.add(null);this.extraData.add(null);this.extraData.add(null);
        this.extraData.add(null);this.extraData.add(null);this.extraData.add(null);
        this.extraData.add(null);this.extraData.add(null);this.extraData.add(null);
    }

    /**
     * c: X509_STORE_set_verify_func
     */
    public void setVerifyFunction(Function1 func) {
        verify = func;
    }

    /**
     * c: X509_STORE_set_verify_cb_func
     */
    public void setVerifyCallbackFunction(Function2 func) {
        verifyCallback = func;
    }

    /**
     * c: X509_STORE_free
     */
    public void free() throws Exception {
        for(Lookup lu : certificateMethods) {
            lu.shutdown();
            lu.free();
        }
        if(param != null) {
            param.free();
        }
    }

    /**
     * c: X509_set_ex_data
     */
    public int setExtraData(int idx,Object data) { 
        extraData.set(idx,data);
        return 1; 
    } 

    /**
     * c: X509_get_ex_data
     */
    public Object getExtraData(int idx) { 
        return extraData.get(idx); 
    }

    /**
     * c: X509_STORE_set_depth
     */
    public int setDepth(int depth) { 
        param.setDepth(depth);
        return 1;
    }

    /**
     * c: X509_STORE_set_flags
     */
    public int setFlags(long flags) { 
        return param.setFlags(flags);
    }

    /**
     * c: X509_STORE_set_purpose
     */
    public int setPurpose(int purpose) { 
        return param.setPurpose(purpose);
    }

    /**
     * c: X509_STORE_set_trust
     */
    public int setTrust(int trust) { 
        return param.setTrust(trust);
    }

    /**
     * c: X509_STORE_set1_param
     */
    public int setParam(VerifyParameter pm) { 
        return param.set(param);
    }

    /**
     * c: X509_STORE_add_lookup
     */
    public Lookup addLookup(LookupMethod m) throws Exception { 
        Lookup lu;

        for(Lookup l : certificateMethods) {
            if(l.equals(m)) {
                return l;
            }
        }
        lu = new Lookup(m);
        lu.store = this;
        certificateMethods.add(lu);
        return lu;
    } 

    /**
     * c: X509_STORE_add_cert
     */
    public int addCertificate(X509Certificate x) { 
        int ret = 1;
        if(x == null) {
            return 0;
        }

        Certificate obj = new Certificate();
        obj.x509 = StoreContext.ensureAux(x);

        synchronized(X509Utils.CRYPTO_LOCK_X509_STORE) {
            if(X509Object.retrieveMatch(objs,obj) != null) {
                X509Error.addError(X509Utils.X509_R_CERT_ALREADY_IN_HASH_TABLE);
                ret=0;
            } else {
                objs.add(obj);
            }
        }
        return ret;
    } 

    /**
     * c: X509_STORE_add_crl
     */
    public int addCRL(java.security.cert.CRL x) { 
        int ret = 1;
        if(null == x) {
            return 0;
        }
        CRL obj = new CRL();
        obj.crl = x;

        synchronized(X509Utils.CRYPTO_LOCK_X509_STORE) {
            if(X509Object.retrieveMatch(objs,obj) != null) {
                X509Error.addError(X509Utils.X509_R_CERT_ALREADY_IN_HASH_TABLE);
                ret=0;
            } else {
                objs.add(obj);
            }
        }
        return ret;
    } 

    /**
     * c: X509_STORE_load_locations
     */
    public int loadLocations(String file, String path) throws Exception { 
        Lookup lookup;

        if(file != null) {
            lookup = addLookup(Lookup.fileLookup());
            if(lookup == null) {
                return 0;
            }
            if(lookup.loadFile(new CertificateFile.Path(file,X509Utils.X509_FILETYPE_PEM)) != 1) {
                return 0;
            }
        }

        if(path != null) {
            lookup = addLookup(Lookup.hashDirLookup());
            if(lookup == null) {
                return 0;
            }
            if(lookup.addDir(new CertificateHashDir.Dir(path,X509Utils.X509_FILETYPE_PEM)) != 1) {
                return 0;
            }
        }
        if((path == null) && (file == null)) {
            return 0;
        }

        return 1;
    } 

    /**
     * c: X509_STORE_set_default_paths
     */
    public int setDefaultPaths() throws Exception { 
        Lookup lookup;

        lookup = addLookup(Lookup.fileLookup());
        if(lookup == null) {
            return 0;
        }

        lookup.loadFile(new CertificateFile.Path(null,X509Utils.X509_FILETYPE_DEFAULT));

        lookup = addLookup(Lookup.hashDirLookup());
        if(lookup == null) {
            return 0;
        }

        lookup.addDir(new CertificateHashDir.Dir(null,X509Utils.X509_FILETYPE_DEFAULT));

        X509Error.clearErrors();

        return 1;
    } 


    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> l = new ArrayList<X509Certificate>();
        for(X509Object o : objs) {
            if(o instanceof Certificate) {
                l.add(((Certificate)o).x509);
            }
        }
        return (X509Certificate[])l.toArray(new X509Certificate[l.size()]);
    }
}// X509_STORE
