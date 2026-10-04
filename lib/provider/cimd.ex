defmodule Bonfire.OpenID.Provider.CIMD do
  @moduledoc """
  Client ID Metadata Documents (CIMD) support.

  When a client_id is an HTTPS URL, fetches client metadata from that URL
  rather than requiring pre-registration, per the IETF Internet-Draft for
  OAuth Client ID Metadata Documents.
  """

  import Untangle

  @timeout_ms 10_000
  @max_body_bytes 5 * 1024

  @doc """
  Returns true if the client_id looks like a CIMD URL (HTTPS).
  """
  def cimd_client_id?(client_id) when is_binary(client_id),
    do: String.starts_with?(client_id, "https://")

  def cimd_client_id?(_), do: false

  @doc """
  Fetch and validate a Client ID Metadata Document.
  Returns `{:ok, map}` or `{:error, reason}`.
  The client record is persisted by the caller via `ClientApps.get_or_new/3`.
  """
  def fetch(url) when is_binary(url) do
    with :ok <- validate_https(url),
         :ok <- validate_ssrf(url),
         {:ok, raw} <- do_fetch(url) do
      validate_doc(raw, url)
    end
  end

  defp validate_https(url) do
    if String.starts_with?(url, "https://"),
      do: :ok,
      else: {:error, "CIMD client_id must be an HTTPS URL"}
  end

  # every address the host resolves to (IPv4 and IPv6) must be public; the fetch also checks each redirect hop
  defp validate_ssrf(url) do
    case Bonfire.Common.HTTP.SSRF.check(url) do
      :ok -> :ok
      {:error, _} -> {:error, "CIMD client_id resolves to a blocked address"}
    end
  end

  defp do_fetch(url) do
    case Req.get(url,
           headers: [accept: "application/json"],
           receive_timeout: @timeout_ms,
           max_redirects: 3,
           plugins: [&Bonfire.Common.HTTP.SSRF.attach/1]
         ) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body}

      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        if byte_size(body) > @max_body_bytes do
          {:error, "CIMD document exceeds maximum allowed size"}
        else
          case Jason.decode(body) do
            {:ok, doc} -> {:ok, doc}
            _ -> {:error, "CIMD document is not valid JSON"}
          end
        end

      {:ok, %{status: status}} ->
        {:error, "CIMD fetch returned HTTP #{status}"}

      {:error, %ReqSSRF.BlockedError{}} ->
        {:error, "CIMD client_id redirects to a blocked address"}

      {:error, reason} ->
        warn(reason, "CIMD fetch failed for #{url}")
        {:error, "CIMD fetch failed"}
    end
  end

  @doc """
  Validate a parsed CIMD document against the URL it was fetched from.
  Exposed publicly so it can be unit-tested and called from integration points.
  """
  def validate_doc(%{"client_id" => doc_client_id} = doc, url) do
    if doc_client_id == url do
      name =
        doc["client_name"] || doc["name"] ||
          case URI.parse(url) do
            %{host: host} when is_binary(host) -> host
            _ -> url
          end

      {:ok,
       %{
         client_id: url,
         name: name,
         redirect_uris:
           List.wrap(doc["redirect_uris"] || doc["redirectURI"] || doc["redirectURIs"]),
         grant_types: doc["grant_types"] || ["authorization_code"],
         scope: doc["scope"],
         logo_uri: doc["logo_uri"],
         client_uri: doc["client_uri"]
       }}
    else
      {:error, "CIMD document client_id does not match the fetched URL"}
    end
  end

  def validate_doc(_, _),
    do: {:error, "CIMD document missing required client_id field"}
end
