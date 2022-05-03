ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(Bonfire.Common.Config.get!(:repo_module), :manual)

# to test openid/oauth
Mox.defmock(Boruta.OauthMock, for: Boruta.OauthModule)
Mox.defmock(Boruta.OpenidMock, for: Boruta.OpenidModule)
