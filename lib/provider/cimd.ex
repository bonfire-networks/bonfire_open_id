defmodule Bonfire.OpenID.Provider.CIMD do
  @moduledoc """
  Client ID Metadata Documents (CIMD) support.

  When a client_id is an HTTPS URL, fetches client metadata from that URL
  rather than requiring pre-registration, per the IETF Internet-Draft for
  OAuth Client ID Metadata Documents.
  """

  import Untangle
  import Bitwise

  @timeout_ms 10_000
  @max_body_bytes 5 * 1024

  # Private IP ranges to block (SSRF protection)
  @blocked_ranges [
    {{127, 0, 0, 0}, 8},
    {{10, 0, 0, 0}, 8},
    {{172, 16, 0, 0}, 12},
    {{192, 168, 0, 0}, 16},
    {{169, 254, 0, 0}, 16},
    {{0, 0, 0, 0, 0, 0, 0, 1}, 128},
    {{0xFE80, 0, 0, 0, 0, 0, 0, 0}, 10}
  ]

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

  defp validate_ssrf(url) do
    with {:ok, %{host: host}} <- URI.new(url),
         {:ok, addresses} <- :inet.getaddrs(String.to_charlist(host), :inet) do
      if Enum.any?(addresses, &ip_blocked?/1),
        do: {:error, "CIMD client_id resolves to a blocked IP address"},
        else: :ok
    else
      _ -> {:error, "Could not resolve CIMD client_id host"}
    end
  end

  defp ip_blocked?(ip) do
    Enum.any?(@blocked_ranges, fn {range_ip, prefix_len} ->
      ip_in_range?(ip, range_ip, prefix_len)
    end)
  end

  defp ip_in_range?(ip, range_ip, prefix_len)
       when tuple_size(ip) == 4 and tuple_size(range_ip) == 4 do
    mask = bnot(bsr(0xFFFFFFFF, prefix_len)) &&& 0xFFFFFFFF
    (ip_to_int32(ip) &&& mask) == (ip_to_int32(range_ip) &&& mask)
  end

  defp ip_in_range?(_, _, _), do: false

  defp ip_to_int32({a, b, c, d}), do: bsl(a, 24) + bsl(b, 16) + bsl(c, 8) + d

  defp do_fetch(url) do
    case Req.get(url,
           headers: [accept: "application/json"],
           receive_timeout: @timeout_ms,
           max_redirects: 3
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
