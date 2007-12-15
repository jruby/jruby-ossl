require 'rake'
require 'rake/testtask'

MANIFEST = FileList["History.txt", "README.txt", "License.txt", "lib/jopenssl.jar", "lib/**/*", "test/**/*"]
BC_JARS = FileList["lib/bc*.jar"]

task :default => [:java_compile, :test]

def java_classpath_arg # myriad of ways to discover JRuby classpath
  begin
    require 'java' # already running in a JRuby JVM
    jruby_cpath = Java::java.lang.System.getProperty('java.class.path')
  rescue LoadError
  end
  unless jruby_cpath
    jruby_cpath = ENV['JRUBY_PARENT_CLASSPATH'] || ENV['JRUBY_HOME'] &&
      FileList["#{ENV['JRUBY_HOME']}/lib/*.jar"].join(File::PATH_SEPARATOR)
  end
  bc_jars = BC_JARS.join(File::PATH_SEPARATOR)
  jruby_cpath ? "-cp #{jruby_cpath}#{File::PATH_SEPARATOR}#{bc_jars}" : "-cp #{bc_jars}"
end

desc "Compile the native Java code."
task :java_compile do
  mkdir_p "pkg/classes"
  sh "javac -target 1.4 -source 1.4 -d pkg/classes #{java_classpath_arg} #{FileList['src/java/**/*.java'].join(' ')}"
  File.open("pkg/classes/manifest.mf", "w") {|f| f.puts "Class-Path: #{BC_JARS.map{|f| File.basename(f) }.join(' ')}"}
  sh "jar cfm lib/jopenssl.jar pkg/classes/manifest.mf -C pkg/classes/ ."
end
file "lib/jopenssl.jar" => :java_compile

task :more_clean do
  rm_f FileList['lib/jopenssl.jar']
end
task :clean => :more_clean

File.open("Manifest.txt", "w") {|f| MANIFEST.each {|n| f.puts n } }

require File.dirname(__FILE__) + "/lib/jopenssl/version"
begin
  require 'hoe'
  Hoe.new("JRuby-OpenSSL", Jopenssl::Version::VERSION) do |p|
    p.rubyforge_name = "jruby-extras"
    p.url = "http://jruby-extras.rubyforge.org/jopenssl"
    p.author = "Ola Bini and JRuby contributors"
    p.email = "ola.bini@gmail.com"
    p.summary = "OpenSSL add-on for JRuby"
    p.changes = p.paragraphs_of('History.txt', 0..1).join("\n\n")
    p.rdoc_pattern = /^(lib\/.*rb)|txt$/
    p.description = p.paragraphs_of('README.txt', 0...1).join("\n\n")
    p.test_globs = FileList["test/test_openssl.rb"]
  end.spec.dependencies.delete_if { |dep| dep.name == "hoe" }
rescue LoadError
  puts "You really need Hoe installed to be able to package this gem"
rescue => e
  puts "ignoring error while loading hoe: #{e.to_s}"
end
