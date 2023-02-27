ExUnit.start(exclude: Bonfire.Common.RuntimeConfig.skip_test_tags())

Ecto.Adapters.SQL.Sandbox.mode(
  Bonfire.Common.Config.repo(),
  :manual
)

# to test openid/oauth
Mox.defmock(Boruta.OauthMock, for: Boruta.OauthModule)
Mox.defmock(Boruta.OpenidMock, for: Boruta.OpenidModule)
