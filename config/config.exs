import Config

#### Email configuration

# You will almost certainly want to change at least some of these

# include Phoenix web server boilerplate
# import_config "bonfire_web_phoenix.exs"

# include all used Bonfire extensions
import_config "bonfire_open_id.exs"

#### Basic configuration

# You probably won't want to touch these. You might override some in
# other config files.

config :phoenix, :json_library, Jason

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

config :mime, :types, %{
  "application/activity+json" => ["activity+json"]
}

config :bonfire_open_id, :otp_app, :bonfire_open_id
config :bonfire_common, :otp_app, :bonfire_open_id
config :bonfire_open_id, :repo_module, Bonfire.Common.Repo
config :bonfire_open_id, ecto_repos: [Bonfire.Common.Repo]
config :bonfire_common, localisation_path: "priv/localisation"
config :bonfire, :endpoint_module, Bonfire.Web.Endpoint

config :bonfire_data_identity, Bonfire.Data.Identity.Credential, hasher_module: Argon2

# import_config "#{Mix.env()}.exs"

config :ex_cldr,
  default_locale: "en",
  default_backend: Bonfire.Common.Localise.Cldr,
  json_library: Jason

config :ecto_sparkles, :otp_app, :bonfire_open_id
config :ecto_sparkles, :env, config_env()
