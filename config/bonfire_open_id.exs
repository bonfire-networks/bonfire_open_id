import Config

config :bonfire_open_id,
  templates_path: "lib"

config :boruta, Boruta.Oauth,
  repo: Bonfire.Repo,
  issuer: "https://bonfirenetworks.org",
  contexts: [
    resource_owners: Bonfire.OpenID.Integration
  ]

# config :bonfire_open_id, :openid_connect_providers,
  # bonfire_cafe: [
  #   discovery_document_uri: "https://bonfire.cafe/.well-known/openid-configuration",
  #   client_id: "CLIENT_ID",
  #   client_secret: "CLIENT_SECRET",
  #   redirect_uri: "https://myinstance.net/",
  #   response_type: "code",
  #   scope: "identity data:public"
  # ]
