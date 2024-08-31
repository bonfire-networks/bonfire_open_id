defmodule Bonfire.OpenID.Web.SignInWithExternalProvidersLive do
  use Bonfire.UI.Common.Web, :stateless_component

  prop label, :any, default: nil
  prop source, :atom, default: nil
end
