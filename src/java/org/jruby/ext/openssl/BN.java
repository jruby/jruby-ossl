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
 * Copyright (C) 2007 William N Dortch <bill.dortch@gmail.com>
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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyKernel;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.CallbackFactory;
import org.jruby.runtime.ClassIndex;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * OpenSSL::BN implementation. Wraps java.math.BigInteger, which provides
 * most functionality directly; the rest is easily derived.
 * 
 * Beware that BN's are mutable -- I don't agree with this approach, but 
 * must conform for compatibility with MRI's implementation. The offending methods
 * are set_bit!, clear_bit!, mask_bits! and copy.<p>
 * 
 * I've included a few operations (& | ^ ~) that aren't defined by MRI/OpenSSL.
 * These are non-portable (i.e., won't work in C-Ruby), so use at your own risk.<p>
 * 
 * @author <a href="mailto:bill.dortch@gmail.com">Bill Dortch</a>
 */
public class BN extends RubyObject {
    private static final long serialVersionUID = -5660938062191525498L;

    private static final BigInteger MAX_INT = BigInteger.valueOf(Integer.MAX_VALUE);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final int DEFAULT_CERTAINTY = 100;
    private static Random _random;
    private static SecureRandom _secureRandom;

    private static ObjectAllocator BN_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new BN(runtime, klass, BigInteger.ZERO);
        }
    };

    public static BN newBN(Ruby runtime, BigInteger value) {
        return new BN(runtime, value != null ? value : BigInteger.ZERO);
    }

    public static void createBN(Ruby runtime, RubyModule ossl) {
        RubyClass openSSLError = ossl.getClass("OpenSSLError");
        ossl.defineClassUnder("BNError", openSSLError, openSSLError.getAllocator());

        RubyClass bn = ossl.defineClassUnder("BN", runtime.getObject(), BN_ALLOCATOR);
        CallbackFactory cf = runtime.callbackFactory(BN.class);

        bn.defineMethod("initialize", cf.getOptMethod("bn_initialize"));
        bn.defineFastMethod("copy", cf.getFastMethod("bn_copy", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("to_s", cf.getFastOptMethod("bn_to_s"));
        bn.defineFastMethod("to_i", cf.getFastMethod("bn_to_i"));
        bn.defineFastMethod("to_bn", cf.getFastMethod("bn_to_bn"));
        bn.defineFastMethod("coerce", cf.getFastMethod("bn_coerce", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("zero?", cf.getFastMethod("bn_is_zero"));
        bn.defineFastMethod("one?", cf.getFastMethod("bn_is_one"));
        bn.defineFastMethod("odd?", cf.getFastMethod("bn_is_odd"));
        bn.defineFastMethod("cmp", cf.getFastMethod("bn_cmp", RubyKernel.IRUBY_OBJECT));
        bn.defineAlias("<=>", "cmp");
        bn.defineFastMethod("ucmp", cf.getFastMethod("bn_ucmp", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("eql?", cf.getFastMethod("bn_eql", RubyKernel.IRUBY_OBJECT));
        bn.defineAlias("==", "eql?");
        bn.defineAlias("===", "eql?");
        
        bn.defineFastMethod("sqr", cf.getFastMethod("bn_sqr"));
        bn.defineFastMethod("+", cf.getFastMethod("bn_add", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("-", cf.getFastMethod("bn_sub", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("*", cf.getFastMethod("bn_mul", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("%", cf.getFastMethod("bn_mod", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("/", cf.getFastMethod("bn_div", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("**", cf.getFastMethod("bn_exp", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("gcd", cf.getFastMethod("bn_gcd", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("mod_sqr", cf.getFastMethod("bn_mod_sqr", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("mod_inverse", cf.getFastMethod("bn_mod_inverse", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("mod_add", cf.getFastMethod("bn_mod_add", RubyKernel.IRUBY_OBJECT, RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("mod_sub", cf.getFastMethod("bn_mod_sub", RubyKernel.IRUBY_OBJECT, RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("mod_mul", cf.getFastMethod("bn_mod_mul", RubyKernel.IRUBY_OBJECT, RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("mod_exp", cf.getFastMethod("bn_mod_exp", RubyKernel.IRUBY_OBJECT, RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("set_bit!", cf.getFastMethod("bn_set_bit", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("clear_bit!", cf.getFastMethod("bn_clear_bit", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("mask_bits!", cf.getFastMethod("bn_mask_bits", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("bit_set?", cf.getFastMethod("bn_is_bit_set", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("<<", cf.getFastMethod("bn_lshift", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod(">>", cf.getFastMethod("bn_rshift", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("num_bits", cf.getFastMethod("bn_num_bits"));
        bn.defineFastMethod("num_bytes", cf.getFastMethod("bn_num_bytes"));
        bn.defineFastMethod("prime?", cf.getFastOptMethod("bn_is_prime"));
        // TODO: faster test for fasttest? need to research...
        bn.defineFastMethod("prime_fasttest?", cf.getFastOptMethod("bn_is_prime"));

        RubyClass  meta = bn.getMetaClass();
        
        meta.defineFastMethod("rand", cf.getFastOptSingletonMethod("bn_rand"));
        meta.defineFastMethod("pseudo_rand", cf.getFastOptSingletonMethod("bn_pseudo_rand"));
        meta.defineFastMethod("rand_range", cf.getFastSingletonMethod("bn_rand_range", RubyKernel.IRUBY_OBJECT));
        meta.defineFastMethod("pseudo_rand_range", cf.getFastSingletonMethod("bn_pseudo_rand_range", RubyKernel.IRUBY_OBJECT));
        meta.defineFastMethod("generate_prime", cf.getFastOptSingletonMethod("bn_generate_prime"));
        
        // non-standard (not defined in MRI's OpenSSL::BN):

        bn.defineFastMethod("~", cf.getFastMethod("bn_not"));
        bn.defineFastMethod("&", cf.getFastMethod("bn_and", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("|", cf.getFastMethod("bn_or", RubyKernel.IRUBY_OBJECT));
        bn.defineFastMethod("^", cf.getFastMethod("bn_xor", RubyKernel.IRUBY_OBJECT));
        // could be used to speed up Net::SSH's DH#valid? method
        bn.defineFastMethod("num_bits_set", cf.getFastMethod("bn_num_bits_set"));
    }

    private volatile BigInteger value;

    private BN(Ruby runtime, RubyClass clazz, BigInteger value) {
        super(runtime, clazz);
        this.value = value;
    }

    private BN(Ruby runtime, BigInteger value) {
        super(runtime, runtime.getModule("OpenSSL").getClass("BN"));
        this.value = value;
    }

    public BigInteger getValue() {
        return value;
    }
    
    // TODO: check whether this is really needed for JRuby 1.0x (not used in 1.1x)
    public IRubyObject doClone() {
        return newBN(getRuntime(), this.value);
    }
    
    public IRubyObject initialize_copy(IRubyObject original) {
        super.initialize_copy(original);
        if (this != original) {
            this.value = ((BN)original).value;
        }
        return this;
    }

    public synchronized IRubyObject bn_initialize(IRubyObject[] args, Block unusedBlock) {
        Ruby runtime = getRuntime();
        if (this.value != BigInteger.ZERO) { // already initialized
            throw newBNError(runtime, "illegal initialization");
        }
        int argc = Arity.checkArgumentCount(runtime, args, 1, 2);
        int base = argc == 2 ? RubyNumeric.num2int(args[1]) : 10;
        RubyString str = RubyString.stringValue(args[0]);
        switch (base) {
        case 2:
            // this seems wrong to me, but is the behavior of the
            // MRI implementation. rather than interpreting the string
            // as ASCII-encoded binary digits, the raw binary value of
            // the string is used instead. the value is always interpreted
            // as positive, hence the use of the signum version of the BI
            // constructor here:
            this.value = new BigInteger(1, str.getBytes());
            break;
        case 10:
        case 16:
            // here, the ASCII-encoded decimal or hex string is used
            try {
                this.value = new BigInteger(str.toString(), base);
                break;
            } catch (NumberFormatException e) {
                throw runtime.newArgumentError("value " + str + " is not legal for radix " + base);
            }
        case 0: // FIXME: not currently supporting BN_mpi2bn
            throw runtime.newArgumentError("unsupported radix: " + base);
        default:
            throw runtime.newArgumentError("illegal radix: " + base);
        }
        return this;
    }
    
    public synchronized IRubyObject bn_copy(IRubyObject other) {
        if (this != other) {
            this.value = getBigInteger(other);
        }
        return this;
    }

    public IRubyObject bn_to_s(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        int argc = Arity.checkArgumentCount(runtime, args, 0, 1);
        int base = argc == 1 ? RubyNumeric.num2int(args[0]) : 10;
        switch (base) {
        case 2:
            // again, following MRI implementation, wherein base 2 deals
            // with strings as byte arrays rather than ASCII-encoded binary
            // digits.  note that negative values are returned as though positive:

            byte[] bytes = this.value.abs().toByteArray();

            // suppress leading 0 byte to conform to MRI behavior
            if (bytes[0] == 0) {
                return runtime.newString(new ByteList(bytes, 1, bytes.length - 1));
            }
            return runtime.newString(new ByteList(bytes, false));
        case 10:
        case 16:
            return runtime.newString(value.toString(base));
        case 0: // FIXME: not currently supporting BN_mpi2bn
            throw runtime.newArgumentError("unsupported radix: " + base);
        default:
            throw runtime.newArgumentError("illegal radix: " + base);
        }
    }

    public IRubyObject bn_to_i() {
        Ruby runtime = getRuntime();
        // FIXME: s/b faster way to convert than going through RubyString
        return RubyNumeric.str2inum(runtime, runtime.newString(value.toString()), 10, true);
    }

    public IRubyObject bn_to_bn() {
        return this;
    }

    // FIXME: is this right? don't see how it would be useful...
    public IRubyObject bn_coerce(IRubyObject other) {
        Ruby runtime = getRuntime();
        IRubyObject self;
        switch (other.getMetaClass().index) {
        case ClassIndex.STRING:
            self = runtime.newString(value.toString());
            break;
        case ClassIndex.FIXNUM:
        case ClassIndex.BIGNUM:
            // FIXME: s/b faster way to convert than going through RubyString
            self = RubyNumeric.str2inum(runtime, runtime.newString(value.toString()), 10, true);
            break;
        default:
            if (other instanceof BN) {
                self = this;
            } else {
                throw runtime.newTypeError("Don't know how to coerce");
            }
        }
        return runtime.newArray(other, self);
    }
    
    public IRubyObject bn_is_zero() {
        return getRuntime().newBoolean(value.equals(BigInteger.ZERO));
    }

    public IRubyObject bn_is_one() {
        return getRuntime().newBoolean(value.equals(BigInteger.ONE));
    }

    public IRubyObject bn_is_odd() {
        return getRuntime().newBoolean(value.testBit(0));
    }
    
    public IRubyObject bn_cmp(IRubyObject other) {
        return getRuntime().newFixnum(value.compareTo(getBigInteger(other)));
    }

    public IRubyObject bn_ucmp(IRubyObject other) {
        return getRuntime().newFixnum(value.abs().compareTo(getBigInteger(other).abs()));
    }
    
    public IRubyObject bn_eql(IRubyObject other) {
        return getRuntime().newBoolean(value.equals(getBigInteger(other)));
    }

    public IRubyObject bn_sqr() {
        // TODO: check whether mult n * n is faster
        return newBN(getRuntime(), value.pow(2));
    }

    public IRubyObject bn_not() {
        return newBN(getRuntime(), value.not());
    }

    public IRubyObject bn_add(IRubyObject other) {
        return newBN(getRuntime(), value.add(getBigInteger(other)));
    }

    public IRubyObject bn_sub(IRubyObject other) {
        return newBN(getRuntime(), value.subtract(getBigInteger(other)));
    }

    public IRubyObject bn_mul(IRubyObject other) {
        return newBN(getRuntime(), value.multiply(getBigInteger(other)));
    }

    public IRubyObject bn_mod(IRubyObject other) {
        try {
            return newBN(getRuntime(), value.mod(getBigInteger(other)));
        } catch (ArithmeticException e) {
            throw getRuntime().newZeroDivisionError();
        }
    }

    public IRubyObject bn_div(IRubyObject other) {
        Ruby runtime = getRuntime();
        try {
            BigInteger[] result = value.divideAndRemainder(getBigInteger(other));
            return runtime.newArray(newBN(runtime, result[0]), newBN(runtime, result[1]));
        } catch (ArithmeticException e) {
            throw runtime.newZeroDivisionError();
        }
    }
    
    public IRubyObject bn_and(IRubyObject other) {
        return newBN(getRuntime(), value.and(getBigInteger(other)));
    }

    public IRubyObject bn_or(IRubyObject other) {
        return newBN(getRuntime(), value.or(getBigInteger(other)));
    }

    public IRubyObject bn_xor(IRubyObject other) {
        return newBN(getRuntime(), value.xor(getBigInteger(other)));
    }

    public IRubyObject bn_exp(IRubyObject other) {
        // somewhat strangely, BigInteger takes int rather than BigInteger
        // as the argument to pow.  so we'll have to narrow the value, and
        // raise an exception if data would be lost. (on the other hand, an
        // exponent even approaching Integer.MAX_VALUE would be silly big, and
        // the value would take a very, very long time to calculate.)
        // we'll check for values < 0 (illegal) while we're at it
        int exp;
        switch(other.getMetaClass().index) {
        case ClassIndex.FIXNUM: {
            long val = ((RubyFixnum)other).getLongValue();
            if (val >= 0 && val <= Integer.MAX_VALUE) {
                exp = (int)val;
                break;
            }
            // drop through for error
        }
        case ClassIndex.BIGNUM:
            // Bignum is inherently too big
            throw newBNError(getRuntime(), "invalid exponent");
        default: {
            if (!(other instanceof BN)) {
                throw getRuntime().newTypeError("Cannot convert into OpenSSL::BN");
            }
            BigInteger val = ((BN)other).value;
            if (val.compareTo(BigInteger.ZERO) < 0 || val.compareTo(MAX_INT) > 0) {
                throw newBNError(getRuntime(), "invalid exponent");
            }
            exp = val.intValue();
            break;
        }
        }
        try {
            return newBN(getRuntime(), value.pow(exp));
        } catch (ArithmeticException e) {
            // shouldn't happen, we've already checked for < 0
            throw newBNError(getRuntime(), "invalid exponent");
        }
    }

    public IRubyObject bn_gcd(IRubyObject other) {
        return newBN(getRuntime(), value.gcd(getBigInteger(other)));
    }

    public IRubyObject bn_mod_sqr(IRubyObject other) {
        try {
            return newBN(getRuntime(), value.modPow(TWO, getBigInteger(other)));
        } catch (ArithmeticException e) {
            throw getRuntime().newZeroDivisionError();
        }
    }
    
    public IRubyObject bn_mod_inverse(IRubyObject other) {
        try {
            return newBN(getRuntime(), value.modInverse(getBigInteger(other)));
        } catch (ArithmeticException e) {
            throw getRuntime().newZeroDivisionError();
        }
    }
    
    public IRubyObject bn_mod_add(IRubyObject other, IRubyObject mod) {
        try {
            return newBN(getRuntime(), value.add(getBigInteger(other)).mod(getBigInteger(mod)));
        } catch (ArithmeticException e) {
            throw getRuntime().newZeroDivisionError();
        }
    }

    public IRubyObject bn_mod_sub(IRubyObject other, IRubyObject mod) {
        try {
            return newBN(getRuntime(), value.subtract(getBigInteger(other)).mod(getBigInteger(mod)));
        } catch (ArithmeticException e) {
            throw getRuntime().newZeroDivisionError();
        }
    }

    public IRubyObject bn_mod_mul(IRubyObject other, IRubyObject mod) {
        try {
            return newBN(getRuntime(), value.multiply(getBigInteger(other)).mod(getBigInteger(mod)));
        } catch (ArithmeticException e) {
            throw getRuntime().newZeroDivisionError();
        }
    }

    public IRubyObject bn_mod_exp(IRubyObject other, IRubyObject mod) {
        try {
            return newBN(getRuntime(), value.modPow(getBigInteger(other), getBigInteger(mod)));
        } catch (ArithmeticException e) {
            throw getRuntime().newZeroDivisionError();
        }
    }
    
    public synchronized IRubyObject bn_set_bit(IRubyObject n) {
        // evil mutable BN
        int pos = RubyNumeric.num2int(n);
        BigInteger oldValue = this.value;
        // FIXME? in MRI/OSSL-BIGNUM, the original sign of a BN is remembered, so if
        // you set the value of an (originally) negative number to zero (through some
        // combination of clear_bit! and/or mask_bits! calls), and later call set_bit!,
        // the resulting value will be negative.  this seems unintuitive and, frankly,
        // wrong, not to mention expensive to carry the extra sign field.
        // I'm not duplicating this behavior here at this time. -BD 
        try {
            if (oldValue.signum() >= 0) {
                this.value = oldValue.setBit(pos);
            } else {
                this.value = oldValue.abs().setBit(pos).negate();
            }
        } catch (ArithmeticException e) {
            throw newBNError(getRuntime(), "invalid pos");
        }
        return this;
    }

    public synchronized IRubyObject bn_clear_bit(IRubyObject n) {
        // evil mutable BN
        int pos = RubyNumeric.num2int(n);
        BigInteger oldValue = this.value;
        try {
            if (oldValue.signum() >= 0) {
                this.value = oldValue.clearBit(pos);
            } else {
                this.value = oldValue.abs().clearBit(pos).negate();
            }
        } catch (ArithmeticException e) {
            throw newBNError(getRuntime(), "invalid pos");
        }
        return this;
    }

    /**
     * Truncates value to n bits 
     */
    public synchronized IRubyObject bn_mask_bits(IRubyObject n) {
        // evil mutable BN

        int pos = RubyNumeric.num2int(n);
        if (pos < 0) throw newBNError(getRuntime(), "invalid pos");
        
        BigInteger oldValue = this.value;

        // TODO: cache 2 ** n values?
        if (oldValue.signum() >= 0) {
            if (oldValue.bitLength() < pos) throw newBNError(getRuntime(), "invalid pos");
            this.value = oldValue.mod(TWO.pow(pos));
        } else {
            BigInteger absValue = oldValue.abs();
            if (absValue.bitLength() < pos) throw newBNError(getRuntime(), "invalid pos");
            this.value = absValue.mod(TWO.pow(pos)).negate();
        }
        
        return this;
    }
    
    public IRubyObject bn_is_bit_set(IRubyObject n) {
        int pos = RubyNumeric.num2int(n);
        BigInteger val = this.value;
        try {
            if (val.signum() >= 0) {
                return getRuntime().newBoolean(val.testBit(pos));
            } else {
                return getRuntime().newBoolean(val.abs().testBit(pos));
            }
        } catch (ArithmeticException e) {
            throw newBNError(getRuntime(), "invalid pos");
        }
    }

    public IRubyObject bn_lshift(IRubyObject n) {
        int nbits = RubyNumeric.num2int(n);
        BigInteger val = this.value;
        if (val.signum() >= 0) {
            return newBN(getRuntime(), val.shiftLeft(nbits));
        } else {
            return newBN(getRuntime(), val.abs().shiftLeft(nbits).negate());
        }
    }

    public IRubyObject bn_rshift(IRubyObject n) {
        int nbits = RubyNumeric.num2int(n);
        BigInteger val = this.value;
        if (val.signum() >= 0) {
            return newBN(getRuntime(), val.shiftRight(nbits));
        } else {
            return newBN(getRuntime(), val.abs().shiftRight(nbits).negate());
        }
    }
    
    public IRubyObject bn_num_bits() {
        return getRuntime().newFixnum(this.value.abs().bitLength());
    }

    public IRubyObject bn_num_bytes() {
        return getRuntime().newFixnum((this.value.abs().bitLength() + 7) / 8);
    }
    
    public IRubyObject bn_num_bits_set() {
        return getRuntime().newFixnum(this.value.abs().bitCount());
    }

    // note that there is a bug in the MRI version, in argument handling,
    // so apparently no one ever calls this...
    public IRubyObject bn_is_prime(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        int argc = Arity.checkArgumentCount(runtime, args, 0, 1);
        // BigInteger#isProbablePrime will actually limit checks to a maximum of 50, 
        // depending on bit count.
        int certainty = argc == 0 ? DEFAULT_CERTAINTY : RubyNumeric.fix2int(args[0]);
        return runtime.newBoolean(this.value.isProbablePrime(certainty));
    }
    
    // FIXME? BigInteger doesn't supply this, so right now this is (essentially)
    // the same as bn_is_prime
    public IRubyObject bn_is_prime_fasttest(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        int argc = Arity.checkArgumentCount(runtime, args, 0, 2);
        // BigInteger#isProbablePrime will actually limit checks to a maximum of 50, 
        // depending on bit count.
        int certainty = argc == 0 ? DEFAULT_CERTAINTY : RubyNumeric.fix2int(args[0]);
        return runtime.newBoolean(this.value.isProbablePrime(certainty));
    }
    
    public static IRubyObject bn_generate_prime(IRubyObject recv, IRubyObject[] args) {
        Ruby runtime = recv.getRuntime();
        int argc = Arity.checkArgumentCount(runtime, args, 1, 4);
        int bits = RubyNumeric.num2int(args[0]);
        boolean safe = argc > 1 ? args[1] != runtime.getFalse() : true;
        BigInteger add = argc > 2 ? getBigInteger(args[2]) : null;
        BigInteger rem = argc > 3 ? getBigInteger(args[3]) : null;
        if (bits < 3) {
            if (safe) throw runtime.newArgumentError("bits < 3");
            if (bits < 2) throw runtime.newArgumentError("bits < 2");
        }
        return newBN(runtime, generatePrime(bits, safe, add, rem));
    }
    
    public static BigInteger generatePrime(int bits, boolean safe, BigInteger add, BigInteger rem) {
        // From OpenSSL man page BN_generate_prime(3):
        //
        // "If add is not NULL, the prime will fulfill the condition p % add == rem 
        // (p % add == 1 if rem == NULL) in order to suit a given generator."
        //
        // "If safe is true, it will be a safe prime (i.e. a prime p so that
        // (p-1)/2 is also prime)."
        //
        // see [ossl]/crypto/bn/bn_prime.c #BN_generate_prime_ex
        //

        if (add != null && rem == null) {
            rem = BigInteger.ONE;
        }
        
        // borrowing technique from org.bouncycastle.crypto.generators.DHParametersHelper
        // (unfortunately the code has package visibility), wherein for safe primes,
        // we'll use the lowest useful certainty (2) for generation of q, then if
        // p ( = 2q + 1) is prime to our required certainty (100), we'll verify that q
        // is as well.
        //
        // for typical bit lengths ( >= 1024), this should speed things up by reducing
        // initial Miller-Rabin iterations from 2 to 1 for candidate values of q.
        //
        // it's still painfully slow...
        //
        BigInteger p, q;
        int qbits = bits - 1;
        SecureRandom secureRandom = getSecureRandom();
        do {
            if (safe) {
                do {
                    q = new BigInteger(qbits, 2, secureRandom);
                    p = q.shiftLeft(1).setBit(0);
                } while (!(p.isProbablePrime(DEFAULT_CERTAINTY) && q.isProbablePrime(DEFAULT_CERTAINTY)));
            } else {
                p = BigInteger.probablePrime(bits, secureRandom); 
            }
        } while (add != null && !p.mod(add).equals(rem));
        return p;
    }
    
    public static BigInteger generatePrime(int bits, boolean safe) {
        return generatePrime(bits, safe, null, null);
    }
    
    public static IRubyObject bn_rand(IRubyObject recv, IRubyObject[] args) {
        return getRandomBN(recv.getRuntime(), args, getSecureRandom()); 
    }
    
    public static IRubyObject bn_pseudo_rand(IRubyObject recv, IRubyObject[] args) {
        return getRandomBN(recv.getRuntime(), args, getRandom()); 
    }
    
    public static BN getRandomBN(Ruby runtime, IRubyObject[] args, Random random) {
        int argc = Arity.checkArgumentCount(runtime, args, 1, 3);
        int bits = RubyNumeric.num2int(args[0]);
        int top;
        boolean bottom;
        if (argc > 1) {
            top = RubyNumeric.fix2int(args[1]);
            bottom = argc == 3 ? args[2].isTrue() : false;
        } else {
            top = 0;
            bottom = false;
        }

        BigInteger value;
        try {
            value = getRandomBI(bits, top, bottom, random);
        } catch (IllegalArgumentException e) {
            throw runtime.newArgumentError(e.getMessage());
        }
        return newBN(runtime, value);
    }
    
    public static BigInteger getRandomBI(int bits, int top, boolean bottom, Random random) {
        // From OpenSSL man page BN_rand(3):
        //
        // "If top is -1, the most significant bit of the random number can be zero.
        // If top is 0, it is set to 1, and if top is 1, the two most significant bits
        // of the number will be set to 1, so that the product of two such random numbers
        // will always have 2*bits length."
        //
        // "If bottom is true, the number will be odd."
        //
        if (bits <= 0) {
            if (bits == 0) return BigInteger.ZERO;
            throw new IllegalArgumentException("Illegal bit length");
        }
        if (top < -1 || top > 1) {
            throw new IllegalArgumentException("Illegal top value");
        }
        
        // top/bottom handling adapted from OpenSSL's crypto/bn/bn_rand.c
        int bytes = (bits + 7) / 8;
        int bit = (bits - 1) % 8;
        int mask = 0xff << (bit + 1);

        byte[] buf;
        random.nextBytes(buf = new byte[bytes]);
        if (top >= 0) {
            if (top == 0) {
                buf[0] |= (1 << bit);
            } else {
                if (bit == 0) {
                    buf[0] = 1;
                    buf[1] |= 0x80;
                }
                else {
                    buf[0] |= (3 << (bit - 1));
                }
            }
        }
        buf[0] &= ~mask;
        if (bottom) {
            buf[bytes-1] |= 1;
        }
        
        // treating result as unsigned
        return new BigInteger(1, buf);
    }
    
    public static IRubyObject bn_rand_range(IRubyObject recv, IRubyObject arg) {
        return getRandomBNInRange(recv.getRuntime(), getBigInteger(arg), getSecureRandom()); 
    }
    
    public static IRubyObject bn_pseudo_rand_range(IRubyObject recv, IRubyObject arg) {
        return getRandomBNInRange(recv.getRuntime(), getBigInteger(arg), getRandom()); 
    }
    
    private static BN getRandomBNInRange(Ruby runtime, BigInteger limit, Random random) {
        BigInteger value;
        try {
            value = getRandomBIInRange(limit, random);
        } catch (IllegalArgumentException e) {
            throw newBNError(runtime, "illegal range");
        }
        return newBN(runtime, value);
    }
    
    public static BigInteger getRandomBIInRange(BigInteger limit, Random random) {
        if (limit.signum() < 0) {
            throw new IllegalArgumentException("illegal range");
        }
        int bits = limit.bitLength();
        BigInteger value;
        do {
            value = new BigInteger(bits, random);
        } while (value.compareTo(limit) >= 0);
        return value;
    }
    
    private static Random getRandom() {
        Random rand;
        if ((rand = _random) != null) {
            return rand;
        }
        return _random = new Random();
    }
    
    private static SecureRandom getSecureRandom() {
        SecureRandom rand;
        if ((rand = _secureRandom) != null) {
            return rand;
        }
        // FIXME: do we want a particular algorithm / provider? BC?
        return _secureRandom = new SecureRandom();
    }

    public static RaiseException newBNError(Ruby runtime, String message) {
        return new RaiseException(runtime, runtime.getModule("OpenSSL").getClass("BNError"), message, true);
    }
    
    public static BigInteger getBigInteger(IRubyObject arg) {
        if (arg.isNil()) return null;
        switch(arg.getMetaClass().index) {
        case ClassIndex.FIXNUM:
        case ClassIndex.BIGNUM:
            return new BigInteger(arg.toString());
        default:
            if (arg instanceof BN) {
                return ((BN)arg).value;
            }
            throw arg.getRuntime().newTypeError("Cannot convert into OpenSSL::BN");
        }
    }

}
