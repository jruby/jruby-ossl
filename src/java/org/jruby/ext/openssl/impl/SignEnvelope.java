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
 * Copyright (C) 2008 Ola Bini <ola.bini@gmail.com>
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
package org.jruby.ext.openssl.impl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.security.cert.X509CRL;

/** PKCS7_SIGN_ENVELOPE
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class SignEnvelope {
    private int version;

    /**
     * Describe encContent here.
     */
    private EncContent encData = new EncContent();

    /**
     * Describe crl here.
     */
    private List<X509CRL> crl = new ArrayList<X509CRL>();

    /**
     * Describe cert here.
     */
    private List<X509Certificate> cert = new ArrayList<X509Certificate>();

    /**
     * Describe mdAlgs here.
     */
    private Set<String> mdAlgs = new HashSet<String>();

    /**
     * Describe signerInfo here.
     */
    private List<SignerInfo> signerInfo = new ArrayList<SignerInfo>();

    /**
     * Describe recipientInfo here.
     */
    private List<RecipInfo> recipientInfo = new ArrayList<RecipInfo>();

    /**
     * Get the <code>Version</code> value.
     *
     * @return an <code>int</code> value
     */
    public final int getVersion() {
        return version;
    }

    /**
     * Set the <code>Version</code> value.
     *
     * @param newVersion The new Version value.
     */
    public final void setVersion(final int newVersion) {
        this.version = newVersion;
    }

    /**
     * Get the <code>EncData</code> value.
     *
     * @return an <code>EncContent</code> value
     */
    public final EncContent getEncData() {
        return encData;
    }

    /**
     * Set the <code>EncData</code> value.
     *
     * @param newEncContent The new EncContent value.
     */
    public final void setEncData(final EncContent newEncData) {
        this.encData = newEncData;
    }

    /**
     * Get the <code>RecipientInfo</code> value.
     *
     * @return a <code>List<RecipInfo></code> value
     */
    public final List<RecipInfo> getRecipientInfo() {
        return recipientInfo;
    }

    /**
     * Set the <code>RecipientInfo</code> value.
     *
     * @param newRecipientInfo The new RecipientInfo value.
     */
    public final void setRecipientInfo(final List<RecipInfo> newRecipientInfo) {
        this.recipientInfo = newRecipientInfo;
    }

    /**
     * Get the <code>SignerInfo</code> value.
     *
     * @return a <code>List<SignerInfo></code> value
     */
    public final List<SignerInfo> getSignerInfo() {
        return signerInfo;
    }

    /**
     * Set the <code>SignerInfo</code> value.
     *
     * @param newSignerInfo The new SignerInfo value.
     */
    public final void setSignerInfo(final List<SignerInfo> newSignerInfo) {
        this.signerInfo = newSignerInfo;
    }

    /**
     * Get the <code>MdAlgs</code> value.
     *
     * @return a <code>Set<String></code> value
     */
    public final Set<String> getMdAlgs() {
        return mdAlgs;
    }

    /**
     * Set the <code>MdAlgs</code> value.
     *
     * @param newMdAlgs The new MdAlgs value.
     */
    public final void setMdAlgs(final Set<String> newMdAlgs) {
        this.mdAlgs = newMdAlgs;
    }

    /**
     * Get the <code>Cert</code> value.
     *
     * @return a <code>List<X509Certificate></code> value
     */
    public final List<X509Certificate> getCert() {
        return cert;
    }

    /**
     * Set the <code>Cert</code> value.
     *
     * @param newCert The new Cert value.
     */
    public final void setCert(final List<X509Certificate> newCert) {
        this.cert = newCert;
    }

    /**
     * Get the <code>Crl</code> value.
     *
     * @return a <code>List<X509CRL></code> value
     */
    public final List<X509CRL> getCrl() {
        return crl;
    }

    /**
     * Set the <code>Crl</code> value.
     *
     * @param newCrl The new Crl value.
     */
    public final void setCrl(final List<X509CRL> newCrl) {
        this.crl = newCrl;
    }
}// SignEnvelope
