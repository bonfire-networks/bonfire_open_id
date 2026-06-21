# Mox mocks for the OAuth/OpenID controller tests.
#
# Defined here (in `test/support`, which is compiled whenever this extension is in
# the test scope — see `Mixer.elixirc_paths(:test)`) rather than only in
# `test_helper.exs`, so that path-scoped runs (e.g. `just test extensions/bonfire_open_id/...`)
# also define the mocks. The umbrella loads only the root `test_helper.exs`, so a
# defmock living solely in this extension's `test_helper.exs` is missing on scoped runs.
Mox.defmock(Boruta.OauthMock, for: Boruta.OauthModule)
Mox.defmock(Boruta.OpenidMock, for: Boruta.OpenidModule)
