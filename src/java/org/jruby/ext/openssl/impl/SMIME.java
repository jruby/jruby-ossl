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

/** SMIME methods for PKCS7
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class SMIME {
    private Mime mime;

    public SMIME(Mime mime) {
        this.mime = mime;
    }

    /* c: SMIME_read_PKCS7
     *
     */
    public PKCS7 readPKCS7(BIO bio, BIO[] bcont) {
        if(bcont != null && bcont.length > 0) {
            bcont[0] = null;
        }

        List<MimeHeader> headers = mime.parseHeaders(bio);
        if(headers == null) {
            throw new PKCS7Exception(PKCS7.F_SMIME_READ_PKCS7, PKCS7.R_MIME_PARSE_ERROR);
        }

        MimeHeader hdr = mime.findHeader(headers, "content-type");
        if(hdr == null || hdr.getValue() == null) {
            throw new PKCS7Exception(PKCS7.F_SMIME_READ_PKCS7, PKCS7.R_NO_CONTENT_TYPE);
        }


        return null;

// 	if(!(hdr = mime_hdr_find(headers, "content-type")) || !hdr->value) {
// 		sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
// 		PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_CONTENT_TYPE);
// 		return NULL;
// 	}

// 	/* Handle multipart/signed */

// 	if(!strcmp(hdr->value, "multipart/signed")) {
// 		/* Split into two parts */
// 		prm = mime_param_find(hdr, "boundary");
// 		if(!prm || !prm->param_value) {
// 			sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
// 			PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_MULTIPART_BOUNDARY);
// 			return NULL;
// 		}
// 		ret = multi_split(bio, prm->param_value, &parts);
// 		sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
// 		if(!ret || (sk_BIO_num(parts) != 2) ) {
// 			PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_MULTIPART_BODY_FAILURE);
// 			sk_BIO_pop_free(parts, BIO_vfree);
// 			return NULL;
// 		}

// 		/* Parse the signature piece */
// 		p7in = sk_BIO_value(parts, 1);

// 		if (!(headers = mime_parse_hdr(p7in))) {
// 			PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_MIME_SIG_PARSE_ERROR);
// 			sk_BIO_pop_free(parts, BIO_vfree);
// 			return NULL;
// 		}

// 		/* Get content type */

// 		if(!(hdr = mime_hdr_find(headers, "content-type")) ||
// 								 !hdr->value) {
// 			sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
// 			PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_SIG_CONTENT_TYPE);
// 			return NULL;
// 		}

// 		if(strcmp(hdr->value, "application/x-pkcs7-signature") &&
// 			strcmp(hdr->value, "application/pkcs7-signature")) {
// 			sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
// 			PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_SIG_INVALID_MIME_TYPE);
// 			ERR_add_error_data(2, "type: ", hdr->value);
// 			sk_BIO_pop_free(parts, BIO_vfree);
// 			return NULL;
// 		}
// 		sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
// 		/* Read in PKCS#7 */
// 		if(!(p7 = B64_read_PKCS7(p7in))) {
// 			PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_PKCS7_SIG_PARSE_ERROR);
// 			sk_BIO_pop_free(parts, BIO_vfree);
// 			return NULL;
// 		}

// 		if(bcont) {
// 			*bcont = sk_BIO_value(parts, 0);
// 			BIO_free(p7in);
// 			sk_BIO_free(parts);
// 		} else sk_BIO_pop_free(parts, BIO_vfree);
// 		return p7;
// 	}
		
// 	/* OK, if not multipart/signed try opaque signature */

// 	if (strcmp (hdr->value, "application/x-pkcs7-mime") &&
// 	    strcmp (hdr->value, "application/pkcs7-mime")) {
// 		PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_INVALID_MIME_TYPE);
// 		ERR_add_error_data(2, "type: ", hdr->value);
// 		sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
// 		return NULL;
// 	}

// 	sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
	
// 	if(!(p7 = B64_read_PKCS7(bio))) {
// 		PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_PKCS7_PARSE_ERROR);
// 		return NULL;
// 	}
// 	return p7;
    }
}
