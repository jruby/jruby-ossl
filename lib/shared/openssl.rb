if defined? JRUBY_VERSION

  # Only load on jruby < 1.7. Starting with jruby 1.7 openssl is included.

  if JRUBY_VERSION =~ /^(\d+\.\d+)/ && $1.to_f < 1.7

    begin
      require 'bouncy-castle-java'
    rescue LoadError
      # runs under restricted mode.
    end
    require 'jopenssl'

    if RUBY_VERSION >= '1.9.0'
      $LOAD_PATH.unshift(File.expand_path('../../1.9', __FILE__))
      load(File.expand_path('../../1.9/openssl.rb', __FILE__))
    else
      $LOAD_PATH.unshift(File.expand_path('../../1.8', __FILE__))
      load(File.expand_path('../../1.8/openssl.rb', __FILE__))
    end

    require 'openssl/pkcs12'

  else

    # We've just loaded this jruby-openssl gem's 'openssl.rb' via a
    # consumers `require 'openssl'`. But we are running jruby 1.7+
    # which contains is own, actively maintained and better
    # openssl. It a bit late to require that alternative 'openssl.rb',
    # so we'll back out the gem's LOAD_PATH changes...

    # Remove any LOAD_PATH that loaded this openssl.rb __FILE__
    $LOAD_PATH.reject! do |p|
      File.identical?( __FILE__, File.join( p, 'openssl.rb' ) )
    end

    # Next load what jruby 1.7+ (1.9|1.8)/openssl.rb should be
    # loading. Note this presents a maintenance issue with any future
    # changes to jruby's openssl.rb. But hopefully this jruby-openssl
    # gem will be long forgotten before any such changes occur.

    require 'jopenssl'
    require 'openssl/bn'
    require 'openssl/cipher'
    require 'openssl/config'
    require 'openssl/digest'

    if RUBY_VERSION >= '1.9.0'
      require 'openssl/ssl-internal'
      require 'openssl/x509-internal'
    else
      require 'openssl/pkcs7'
      require 'openssl/ssl'
      require 'openssl/x509'
    end

  end

else
  warn 'Loading jruby-openssl in a non-JRuby interpreter'
end
