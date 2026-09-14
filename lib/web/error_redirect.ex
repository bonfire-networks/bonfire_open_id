defmodule Bonfire.OpenID.Web.ErrorRedirect do
  @moduledoc """
  Builds the redirect URL for a Boruta authorization `%Error{}`.

  Boruta's `Error.redirect_to_url/1` concatenates `?` onto the redirect URI, which corrupts
  callbacks that already carry a query string. Query-format errors are merged into the
  existing query instead; fragment-format errors are unaffected and stay with Boruta.
  """

  alias Boruta.Oauth.Error

  def url(%Error{format: :query, redirect_uri: redirect_uri} = error) do
    redirect_uri
    |> Bonfire.Common.URIs.append_params_uri(%{
      error: error.error,
      error_description: error.error_description,
      state: error.state
    })
    |> URI.to_string()
  end

  def url(%Error{} = error), do: Error.redirect_to_url(error)
end
