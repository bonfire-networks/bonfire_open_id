defmodule Bonfire.OpenID.Provider.CIMDTest do
  use ExUnit.Case, async: true

  alias Bonfire.OpenID.Provider.CIMD

  describe "cimd_client_id?/1" do
    test "returns true for HTTPS URLs" do
      assert CIMD.cimd_client_id?("https://client.example.com/oauth/metadata")
      assert CIMD.cimd_client_id?("https://example.com")
    end

    test "returns false for HTTP, plain IDs, nil" do
      refute CIMD.cimd_client_id?("http://client.example.com")
      refute CIMD.cimd_client_id?("some-uuid-client-id")
      refute CIMD.cimd_client_id?("a1b2c3d4-0000-0000-0000-000000000000")
      refute CIMD.cimd_client_id?(nil)
    end
  end

  describe "fetch/1 — URL validation" do
    test "rejects HTTP URLs without a network call" do
      assert {:error, msg} = CIMD.fetch("http://example.com/metadata")
      assert msg =~ "HTTPS"
    end
  end

  describe "fetch/1 — SSRF protection" do
    test "rejects localhost" do
      assert {:error, msg} = CIMD.fetch("https://localhost/metadata")
      assert msg =~ "blocked"
    end

    test "rejects 127.0.0.1" do
      assert {:error, msg} = CIMD.fetch("https://127.0.0.1/metadata")
      assert msg =~ "blocked"
    end
  end

  describe "validate_doc/2" do
    test "returns normalised fields on success" do
      doc = %{
        "client_id" => "https://app.example.com",
        "redirect_uris" => ["https://app.example.com/callback"],
        "client_name" => "My App",
        "grant_types" => ["authorization_code", "refresh_token"],
        "scope" => "read write"
      }

      assert {:ok,
              %{
                name: "My App",
                redirect_uris: ["https://app.example.com/callback"],
                grant_types: ["authorization_code", "refresh_token"],
                scope: "read write",
                client_id: "https://app.example.com"
              }} =
               CIMD.validate_doc(doc, "https://app.example.com")
    end

    test "falls back to hostname for name when client_name absent" do
      doc = %{"client_id" => "https://app.example.com", "redirect_uris" => []}
      assert {:ok, %{name: "app.example.com"}} = CIMD.validate_doc(doc, "https://app.example.com")
    end

    test "empty redirect_uris is allowed (request uri used as fallback)" do
      doc = %{"client_id" => "https://app.example.com", "redirect_uris" => []}
      assert {:ok, %{redirect_uris: []}} = CIMD.validate_doc(doc, "https://app.example.com")
    end

    test "missing redirect_uris is allowed" do
      doc = %{"client_id" => "https://app.example.com"}
      assert {:ok, %{redirect_uris: []}} = CIMD.validate_doc(doc, "https://app.example.com")
    end

    test "rejects when client_id does not match the URL" do
      doc = %{"client_id" => "https://different.example.com", "redirect_uris" => []}
      assert {:error, msg} = CIMD.validate_doc(doc, "https://app.example.com")
      assert msg =~ "does not match"
    end

    test "rejects when client_id is missing" do
      doc = %{"redirect_uris" => ["https://app.example.com/callback"]}
      assert {:error, msg} = CIMD.validate_doc(doc, "https://app.example.com")
      assert msg =~ "client_id"
    end

    test "defaults grant_types to authorization_code" do
      doc = %{"client_id" => "https://app.example.com"}

      assert {:ok, %{grant_types: ["authorization_code"]}} =
               CIMD.validate_doc(doc, "https://app.example.com")
    end
  end

  describe "oauth server metadata" do
    test "declares client_id_metadata_document_supported" do
      metadata = Bonfire.OpenID.Provider.oauth_authorization_server_data()
      assert metadata["client_id_metadata_document_supported"] == true
    end
  end
end
