module PKCS7Test
  class TestJavaMime < Test::Unit::TestCase
    def test_find_header_returns_null_on_nonexisting_header
      headers = []
      assert_nil Mime::DEFAULT.find_header(headers, "foo")

      headers = [MimeHeader.new("blarg", "bluff")]
      assert_nil Mime::DEFAULT.find_header(headers, "foo")
    end

    def test_find_header_returns_the_header_with_the_same_name
      hdr = MimeHeader.new("one", "two")
      assert_equal hdr, Mime::DEFAULT.find_header([hdr], "one")
    end

    def test_find_param_returns_null_on_nonexisting_param
      assert_nil Mime::DEFAULT.find_param(MimeHeader.new("one", "two", []), "foo")
      assert_nil Mime::DEFAULT.find_param(MimeHeader.new("one", "two", [MimeParam.new("hi", "ho")]), "foo")
    end

    def test_find_param_returns_the_param_with_the_same_name
      par = MimeParam.new("hox", "box")
      hdr = MimeHeader.new("one", "two", [par])
      assert_equal par, Mime::DEFAULT.find_param(hdr, "hox")
    end
    
    def test_simple_parse_headers
      bio = BIO::from_string("Foo: bar")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result.first
      assert_equal "foo", result.first.name
    end

    def test_simple_parse_headers2
      bio = BIO::from_string("Foo:bar")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result.first
      assert_equal "foo", result.first.name
    end

    def test_simple_parse_headers3
      bio = BIO::from_string("Foo: bar")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result.first
      assert_equal "foo", result.first.name
    end

    def test_simple_parse_headers4
      bio = BIO::from_string("Foo: bar\n")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result.first
      assert_equal "foo", result.first.name
    end

    def test_simple_parse_headers5
      bio = BIO::from_string("     Foo        :                    bar    \n")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result.first
      assert_equal "foo", result.first.name
    end


    def test_simple_parse_headers6
      bio = BIO::from_string("Foo: bar;\n")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result.first
      assert_equal "foo", result.first.name
    end

    def test_simple_parse_headers7
      bio = BIO::from_string("Foo: bar;\nFlurg: blarg")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 2, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result[0]
      assert_equal MimeHeader.new("Flurg", "blarg"), result[1]
      assert_equal "foo", result[0].name
      assert_equal "flurg", result[1].name
    end

    def test_simple_parse_headers_quotes
      bio = BIO::from_string("Foo: \"bar\"")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "bar"), result[0]
      assert_equal "foo", result.first.name
    end

    def test_simple_parse_headers_comment
      bio = BIO::from_string("Foo: (this is the right thing)ba(and this is the wrong one)r")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      assert_equal MimeHeader.new("Foo", "(this is the right thing)ba(and this is the wrong one)r"), result[0]
      assert_equal "foo", result.first.name
    end

    def test_parse_headers_with_param
      bio = BIO::from_string("Content-Type: Multipart/Related; boundary=MIME_boundary; type=text/xml")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      header = result.first
      assert_equal "content-type", header.name
      assert_equal "multipart/related", header.value
      assert_equal [MimeParam.new("boundary","MIME_boundary"), 
                    MimeParam.new("type","text/xml")], header.params.to_a
    end

    def test_parse_headers_with_param_newline
      bio = BIO::from_string("Content-Type: Multipart/Related\n boundary=MIME_boundary; type=text/xml")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      header = result.first
      assert_equal "content-type", header.name
      assert_equal "multipart/related", header.value
      assert_equal [MimeParam.new("boundary","MIME_boundary"), 
                    MimeParam.new("type","text/xml")], header.params.to_a
    end

    def test_parse_headers_with_param_newline_and_semicolon
      bio = BIO::from_string("Content-Type: Multipart/Related;\n boundary=MIME_boundary;\n Type=text/xml")
      result = Mime::DEFAULT.parse_headers(bio)
      assert_equal 1, result.size
      header = result.first
      assert_equal "content-type", header.name
      assert_equal "multipart/related", header.value
      assert_equal [MimeParam.new("boundary","MIME_boundary"), 
                    MimeParam.new("type","text/xml")], header.params.to_a
    end
  end
end
