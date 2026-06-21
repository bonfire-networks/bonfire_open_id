ExUnit.start(exclude: Bonfire.Common.RuntimeConfig.skip_test_tags())

Ecto.Adapters.SQL.Sandbox.mode(
  Bonfire.Common.Config.repo(),
  :manual
)

# NOTE: the OAuth/OpenID Mox mocks are defined in `test/support/mocks.ex` so they
# load on path-scoped runs too (the umbrella only loads the root test_helper.exs).
