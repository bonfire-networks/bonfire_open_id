defmodule Bonfire.OpenID.Provider.OAuth do
  def redirect_uri_validate(nil), do: "empty values are not allowed"

  def redirect_uri_validate("com.tapbots.Ivory.19300:/request_token" <> _rest) do
    :ok
  end

  def redirect_uri_validate("" <> uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host, fragment: fragment}
      when not is_nil(scheme) and not is_nil(host) and is_nil(fragment) ->
        # valid uri
        :ok

      _ ->
        "`#{uri}` is invalid"
    end
  end
end
