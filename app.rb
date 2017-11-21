require 'sinatra'
require 'sinatra/reloader' if development?
require 'fileutils'
require 'json'

PASSWD_PATH = File.join(__dir__, '.passwd')
REALM = 'OneWiki Authorization'

def create_passwd(path)
  require 'readline'
  require 'digest/md5'
  user_id = nil
  user_passwd = nil
  loop do
    user_id = Readline.readline 'ID: '
    break unless user_id.empty?
  end
  loop do
    user_passwd = STDIN.noecho { Readline.readline('Password: ').tap { puts } }
    next if user_passwd.empty?
    conf_passwd = STDIN.noecho { Readline.readline('Confirm: ').tap { puts } }
    break if user_passwd == conf_passwd
  end
  hashed_passwd = Digest::MD5.hexdigest([user_id, REALM, user_passwd].join(':'))
  File.write(path, "#{user_id}:#{hashed_passwd}\n")
end

def load_passwd(path)
  {}.tap do |h|
    File.foreach(path) do |line|
      id, passwd = line.chomp.split(':')
      h[id] = passwd
    end
  end
end

create_passwd(PASSWD_PATH) unless File.file?(PASSWD_PATH)
PASSWD_LIST = load_passwd(PASSWD_PATH)

DATA_DIR = File.join(__dir__, 'data')
FREE_PATTERN = %r{/.*}

enable :inline_templates
set(:action) { |action| condition { params[:action] == action.to_s } }

helpers do
  def authorize!
    response = Rack::Auth::Digest::MD5.new(
      :itself.to_proc,
      realm: REALM,
      opaque: $$.to_s, # humm
      passwords_hashed: true
    ) do |username|
      PASSWD_LIST[username]
    end.call(request.env)
    throw :halt, response if response.first == 401
  end

  def path_directory?
    File.extname(get_request_path).empty?
  end

  def get_request_path
    path = request.path_info.chomp('/')
    path.empty? ? '/' : path # starts from '/'
  end

  def get_data_path
    File.join(DATA_DIR, request.path_info).chomp('/')
  end

  def send_static_file(path)
    # cf. https://github.com/sinatra/sinatra/blob/ee5776e1ae76739df8f59dfa119c4afb6bbc19c0/lib/sinatra/base.rb#L1061-L1069
    env['sinatra.static_file'] = path
    cache_control(*settings.static_cache_control) if settings.static_cache_control?
    send_file path, disposition: nil
  end

  def data_path_to_request_path(path)
    return unless path.start_with?(DATA_DIR)
    path[DATA_DIR.size..-1]
  end

  def haml_use_file_or_template(name, *args)
    data = name
    unless params[:default]
      path = File.join(DATA_DIR, ".#{name}.haml")
      data = File.read(path) if File.file?(path)
    end
    haml data, *args
  end
end

post FREE_PATTERN do
  authorize!
  halt 403, "Directory can't be updated" if path_directory?

  request_path = get_request_path
  data_path = get_data_path

  if params[:file].nil? && params[:body].empty?
    File.unlink(data_path)
    dir_path = File.dirname(request_path) # It's safer than `data_path`.
    loop do
      break if dir_path == '/'
      path = File.join(DATA_DIR, dir_path)
      break unless Dir.empty?(path)
      Dir.unlink(path)
      dir_path = File.dirname(dir_path)
    end
  else
    FileUtils.mkdir_p(File.dirname(data_path))
    if params[:file]
      File.binwrite(data_path, params[:file][:tempfile].read)
    else
      File.write(data_path, params[:body])
    end
  end

  redirect "#{request_path}?action=edit"
end

get FREE_PATTERN, action: :edit do
  authorize!

  @path = get_request_path
  data_path = get_data_path

  if path_directory?
    @matches = Dir.glob(File.join(data_path, '*'), File::FNM_DOTMATCH).map do |path|
      data_path_to_request_path(path) unless /\/\.\.?\z/ =~ path
    end.compact
    haml_use_file_or_template :list, layout: false
  else
    @body = File.read(data_path) if File.file?(data_path) # Binary is also loaded
    haml_use_file_or_template :edit, layout: false
  end
end

get FREE_PATTERN do
  request_path = get_request_path
  data_path = get_data_path
  send_static_file(data_path) if File.file?(data_path)

  if path_directory?
    guessed_data_path = Dir.glob("#{data_path}{.html,/index.html}").first # Guess as HTML
    send_static_file(guessed_data_path) if guessed_data_path && File.file?(guessed_data_path)
    altered_data_path = Dir.glob("#{data_path}{.*,/index.*}").first # Guess as any file
  elsif File.extname(data_path) == '.html'
    altered_data_path = Dir.glob(data_path.sub(/html\z/, '*')).first # Guess as any file
  end

  pass unless altered_data_path

  @path = data_path_to_request_path(altered_data_path)
  raise "Broken #{altered_data_path}" unless @path

  case File.extname(@path)
  when '.haml'
    haml File.read(altered_data_path), layout: false
  else
    haml_use_file_or_template :redirect, layout: false
  end
end

__END__

@@ list

!!!
%html
  %head
    %meta{ charset: 'UTF-8' }
    %title List: #{@path}
  %body
    %ul
      - @matches.each do |path|
        %li
          %a{ href: "#{path}?action=edit" }= path

@@ edit

!!!
%html
  %head
    %meta{ charset: 'UTF-8' }
    %title Edit: #{@path}
  %body
    %form{ method: 'POST', action: @path, enctype: 'multipart/form-data' }
      .row
        %button{ type: 'submit' } update
        %input{ type: 'file', name: 'file' }
      .row
        %textarea{ name: 'body', rows: 30, cols: 80 }= @body

@@ redirect

%html
  %head
    %meta{ charset: 'UTF-8' }
    %title Redirect: #{@path}
    - unless settings.development?
      %meta{ 'http-equiv': 'refresh', content: "0; URL=#{@path}" }
      %script
        :plain
          location.replace(#{@path.to_json})
  %body
    %p
      %a{ href: @path }= @path
