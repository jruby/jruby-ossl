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

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;

/** c: X509_ALGOR
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class AlgorithmIdentifier {
    /**
     * Describe algorithm here.
     */
    private int algorithm;

    /**
     * Describe parameter here.
     */
    private ASN1Encodable parameter;

    /**
     * @param algorithm Description here
     * @param parameter Description here
     */
    public AlgorithmIdentifier(int algorithm, ASN1Encodable parameter) {
        this.algorithm = algorithm;
        this.parameter = parameter;
    }

    /**
     * Get the <code>Algorithm</code> value.
     *
     * @return an <code>int</code> value
     */
    public final int getAlgorithm() {
        return algorithm;
    }

    /**
     * Set the <code>Algorithm</code> value.
     *
     * @param newAlgorithm The new Algorithm value.
     */
    public final void setAlgorithm(final int newAlgorithm) {
        this.algorithm = newAlgorithm;
    }

    /**
     * Get the <code>Parameter</code> value.
     *
     * @return an <code>ASN1Encodable</code> value
     */
    public final ASN1Encodable getParameter() {
        return parameter;
    }

    /**
     * Set the <code>Parameter</code> value.
     *
     * @param newParameter The new Parameter value.
     */
    public final void setParameter(final ASN1Encodable newParameter) {
        this.parameter = newParameter;
    }
    
    @Override
    public boolean equals(Object other) {
        boolean ret = this == other;
        if(!ret && (other instanceof AlgorithmIdentifier)) {
            AlgorithmIdentifier o = (AlgorithmIdentifier)other;
            ret = 
                this.algorithm == o.algorithm &&
                (this.parameter == null) ? o.parameter == null : (this.parameter.equals(o.parameter));
        }
        return ret;
    }

    @Override
    public int hashCode() {
        int ret = 33;
        ret = ret + 13 * algorithm;
        ret = ret + (parameter == null ? 0 : 13 * parameter.hashCode());
        return ret;
    }

    @Override
    public String toString() {
        if(parameter == null) {
            return "#<Algorithm " + ASN1Registry.nid2ln(algorithm) + ">";
        } else {
            return "#<Algorithm " + ASN1Registry.nid2ln(algorithm) + " ;; " + parameter + ">";
        }
    }

    /**
     * AlgorithmIdentifier ::= SEQUENCE {
     *   algorithm  OBJECT IDENTIFIER,
     *   parameters ANY DEFINED BY algorithm OPTIONAL }
     *
     */
    public static AlgorithmIdentifier fromASN1(DEREncodable content) {
        ASN1Sequence sequence = (ASN1Sequence)content;
        int algo = ASN1Registry.obj2nid((DERObjectIdentifier)sequence.getObjectAt(0));
        AlgorithmIdentifier ai = new AlgorithmIdentifier(algo, null);
        if(sequence.size() > 1) {
            ai.setParameter((ASN1Encodable)sequence.getObjectAt(1));
        }
        return ai;
    }

    /**
     * SET OF AlgorithmIdentifier
     *
     */
    public static Set<AlgorithmIdentifier> fromASN1Set(DEREncodable content) {
        ASN1Set set = (ASN1Set)content;
        Set<AlgorithmIdentifier> result = new HashSet<AlgorithmIdentifier>();
        for(Enumeration<?> e = set.getObjects(); e.hasMoreElements();) {
            result.add(fromASN1((DEREncodable)(e.nextElement())));
        }
        return result;
    }
}// AlgorithmIdentifier

