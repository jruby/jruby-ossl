require 'rake'
require 'rake/testtask'

MANIFEST = FileList["Rakefile", "History.txt", "Manifest.txt", "README.txt", "License.txt", "lib/shared/jopenssl.jar", "lib/**/*", "test/**/*"].
           reject { |f| File.directory? f }
BC_JARS = FileList["build_lib/bc*.jar"]

task :default => [:java_compile, :test]

def java_classpath_arg # myriad of ways to discover JRuby classpath
  begin
    cpath  = Java::java.lang.System.getProperty('java.class.path').split(File::PATH_SEPARATOR)
    cpath += Java::java.lang.System.getProperty('sun.boot.class.path').split(File::PATH_SEPARATOR)
    jruby_cpath = cpath.compact.join(File::PATH_SEPARATOR)
  rescue => e
  end
  unless jruby_cpath
    jruby_cpath = ENV['JRUBY_PARENT_CLASSPATH'] || ENV['JRUBY_HOME'] &&
      FileList["#{ENV['JRUBY_HOME']}/lib/*.jar"].join(File::PATH_SEPARATOR)
  end
  bc_jars = BC_JARS.join(File::PATH_SEPARATOR)
  jruby_cpath ? "-cp \"#{jruby_cpath.gsub('\\', '/')}#{File::PATH_SEPARATOR}#{bc_jars}\"" : "-cp \"#{bc_jars}\""
end

desc "Compile the native Java code."
task :java_compile do
  mkdir_p "pkg/classes"

  File.open("pkg/compile_options", "w") do |f|
    f << "-g -target 1.5 -source 1.5 -Xlint:unchecked -Xlint:deprecation -d pkg/classes"
  end

  File.open("pkg/compile_classpath", "w") do |f|
    f << java_classpath_arg
  end

  File.open("pkg/compile_sourcefiles", "w") do |f|
    f << FileList['src/java/**/*.java'].join(' ')
  end

  sh "javac @pkg/compile_options @pkg/compile_classpath @pkg/compile_sourcefiles"
  sh "jar cf lib/shared/jopenssl.jar -C pkg/classes/ ."
end
file "lib/shared/jopenssl.jar" => :java_compile

task :more_clean do
  rm_f FileList['lib/shared/jopenssl.jar']
end
task :clean => :more_clean

File.open("Manifest.txt", "w") {|f| MANIFEST.each {|n| f.puts n } }

begin
  # easiest way to configure ruby_flags for Hoe.
  ENV['RUBY_FLAGS'] ||= [
    (RUBY_VERSION >= '1.9.0' ? '--1.9' : '--1.8'),
    '-w',
    '-Ibuild_lib:lib/shared:lib:test',
    '-J-ea',
    ENV['RUBY_DEBUG']
  ].compact.join(' ')
  require 'hoe'
  Hoe.plugin :gemcutter
  hoe = Hoe.spec("jruby-openssl") do |p|
    load File.dirname(__FILE__) + "/lib/shared/jopenssl/version.rb"
    p.version = Jopenssl::Version::VERSION
    p.rubyforge_name = "jruby-extras"
    p.urls = ["https://github.com/jruby/jruby-ossl"]
    p.author = "Ola Bini and JRuby contributors"
    p.email = "ola.bini@gmail.com"
    p.summary = "OpenSSL add-on for JRuby"
    p.changes = p.paragraphs_of('History.txt', 0..1).join("\n\n")
    p.description = p.paragraphs_of('README.txt', 3...4).join("\n\n")
    p.test_globs = ENV["TEST"] || ["test/test_all.rb"]
    p.extra_deps << ['bouncy-castle-java', '>= 1.5.0146.1']
  end
  hoe.spec.dependencies.delete_if { |dep| dep.name == "hoe" }
  # Either lib/1.8 or lib/1.9 is added to $LOAD_PATH dynamically.
  hoe.spec.require_paths = ['lib/shared']

  task :gemspec do
    File.open("#{hoe.name}.gemspec", "w") {|f| f << hoe.spec.to_ruby }
  end
  task :package => :gemspec
rescue LoadError
  puts "You really need Hoe installed to be able to package this gem"
rescue => e
  puts "ignoring error while loading hoe: #{e.to_s}"
end
