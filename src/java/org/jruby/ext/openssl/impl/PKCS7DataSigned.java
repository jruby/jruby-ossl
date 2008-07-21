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

import java.util.List;
import java.security.cert.X509Certificate;

/**
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class PKCS7DataSigned extends PKCS7Data {
    private int detached;

    /* NID_pkcs7_signed */
    private Signed sign;

    public PKCS7DataSigned() {
        this.sign = new Signed();
        this.sign.setVersion(1);
    }

    public int getType() {
        return PKCS7.NID_pkcs7_signed;
    }

    public Object ctrl(int cmd, Object v, Object ignored) {
        int ret = 0;
        switch(cmd) {
        case PKCS7.OP_SET_DETACHED_SIGNATURE:
            ret = detached = ((Integer)v).intValue();
            if(ret != 0 && sign.contents.isData()) {
                sign.contents.setData(null);
            }
            break;
        case PKCS7.OP_GET_DETACHED_SIGNATURE:
            if(sign == null || sign.contents.getData() == null) {
                ret = 1;
            } else {
                ret = 0;
            }
            break;
        default:
            // TODO: ERR
            ret = 0;
        }
        return Integer.valueOf(ret);
    }

    public void setSign(Signed sign) {
        this.sign = sign;
    }

    public Signed getSign() {
        return this.sign;
    }

    public boolean isSigned() {
        return true;
    }

    public void addSigner(SignerInfo psi) {
        this.sign.getMdAlgs().add(psi.getDigestAlgorithm());
        this.sign.getSignerInfo().add(psi);
    }

    public void setContent(PKCS7 p7) {
        this.sign.setContents(p7);
    }

    public List<SignerInfo> getSignerInfo() {
        return this.sign.getSignerInfo();
    }

    public void addCertificate(X509Certificate cert) {
        this.sign.getCert().add(cert);
    }
}// PKCS7DataSigned
