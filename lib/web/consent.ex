defmodule Bonfire.OpenID.Web.Consent do
  @moduledoc """
  Helpers for the OAuth/OpenID scope-consent screen.

  Consent is remembered in a long-lived cache (keyed by user + client + scopes) so the
  screen is only shown the first time a user authorizes a given client for a given set of
  scopes. A persisted schema can replace this cache later.
  """
  use Bonfire.Common.Utils
  alias Bonfire.Common.Cache

  # 30 days
  @consent_ttl 1_000 * 60 * 60 * 24 * 30

  @doc "Has the given user already consented to this client + scopes?"
  def consented?(user, client_id, scopes) do
    case id(user) do
      nil ->
        false

      uid ->
        Cache.get!(consent_key(uid, client_id, scopes)) == true or
          Cache.get!(consent_all_key(uid)) == true
    end
  end

  @doc "Remember that the user consented to this client + scopes."
  def remember_consent(user, client_id, scopes) do
    case id(user) do
      nil -> nil
      uid -> Cache.put(consent_key(uid, client_id, scopes), true, ttl: @consent_ttl)
    end
  end

  @doc "Remember consent for any client + scopes for this user (used to bypass the screen in tests that aren't exercising consent)."
  def remember_consent_all(user) do
    case id(user) do
      nil -> nil
      uid -> Cache.put(consent_all_key(uid), true, ttl: @consent_ttl)
    end
  end

  defp consent_key(uid, client_id, scopes),
    do: {:oauth_consent, uid, to_string(client_id), normalize_scopes(scopes)}

  defp consent_all_key(uid), do: {:oauth_consent_all, uid}

  defp normalize_scopes(scopes),
    do: scopes |> scope_list() |> Enum.map(&to_string/1) |> Enum.sort()

  @doc "Split a space-separated scope string into a list of scope names."
  def scope_list(nil), do: []
  def scope_list(scope) when is_binary(scope), do: String.split(scope, " ", trim: true)
  def scope_list(list) when is_list(list), do: list
  def scope_list(_), do: []

  @doc "Build a list of `%{name, label}` for display, from a requested scope string and the client's authorized scopes (which carry human-readable labels)."
  def scopes_for_display(requested_scope, client) do
    labels =
      (e(client, :authorized_scopes, []) || [])
      |> Map.new(fn s -> {to_string(e(s, :name, nil)), e(s, :label, nil)} end)

    requested_scope
    |> scope_list()
    |> Enum.map(fn name -> %{name: name, label: Map.get(labels, name)} end)
  end
end
