defmodule Bonfire.OpenID.Provider.Tokens do
  @moduledoc """
  Read/manage a user's own OAuth access tokens (backed by Boruta).
  """

  import Untangle
  import Ecto.Query
  import Boruta.Config, only: [repo: 0]

  alias Boruta.Ecto.Token
  alias Boruta.Ecto.OauthMapper

  @doc """
  Lists the user's active (non-revoked, non-expired) access tokens, newest first.

  ## Options
  - `:limit` - max number of tokens (default 20)
  - `:max_id` - return tokens older than this token id
  - `:min_id` / `:since_id` - return tokens newer than this token id
  """
  def list_for_user(user_id, opts \\ []) when is_binary(user_id) do
    limit = opts[:limit] || 20

    active_tokens_query(user_id)
    |> apply_cursors(user_id, opts)
    |> order_by([t], desc: t.inserted_at, desc: t.id)
    |> limit(^limit)
    |> repo().all()
    |> repo().preload(:client)
  end

  @doc """
  Fetches one of the user's tokens by id, regardless of revoked/expired state
  (so the response to a just-invalidated token still resolves).
  """
  def get_for_user(user_id, token_id) when is_binary(user_id) and is_binary(token_id) do
    # token ids are Boruta UUIDs; a malformed id is simply "not found" (avoid a cast crash)
    with {:ok, uuid} <- Ecto.UUID.cast(token_id),
         %Token{} = token <-
           repo().one(
             from(t in Token,
               where: t.id == ^uuid and t.sub == ^user_id and t.type == "access_token"
             )
           ) do
      {:ok, repo().preload(token, :client)}
    else
      _ -> {:error, :not_found}
    end
  end

  def get_for_user(_, _), do: {:error, :not_found}

  @doc """
  Revokes (invalidates) one of the user's tokens, making it immediately unusable.

  Delegates to Boruta's `revoke/1` so the token cache is invalidated too, then
  returns the updated token for the response.
  """
  def invalidate_for_user(user_id, token_id) do
    with {:ok, token} <- get_for_user(user_id, token_id) do
      token
      |> OauthMapper.to_oauth_schema()
      |> Boruta.Ecto.AccessTokens.revoke()
      |> case do
        {:error, reason} -> debug(reason, "token revoke returned error (continuing)")
        _ -> :ok
      end

      # re-fetch to reflect revoked_at in the response
      get_for_user(user_id, token_id)
    end
  end

  defp active_tokens_query(user_id) do
    now = :os.system_time(:seconds)

    from(t in Token,
      where:
        t.sub == ^user_id and t.type == "access_token" and
          is_nil(t.revoked_at) and t.expires_at >= ^now
    )
  end

  # Cursor pagination by inserted_at (token ids are UUIDs, not chronologically sortable).
  defp apply_cursors(query, user_id, opts) do
    query
    |> maybe_cursor(user_id, opts[:max_id], :older)
    |> maybe_cursor(user_id, opts[:since_id] || opts[:min_id], :newer)
  end

  defp maybe_cursor(query, _user_id, nil, _dir), do: query
  defp maybe_cursor(query, _user_id, "", _dir), do: query

  defp maybe_cursor(query, user_id, cursor_id, dir) do
    case cursor_time(user_id, cursor_id) do
      nil -> query
      at when dir == :older -> where(query, [t], t.inserted_at < ^at)
      at -> where(query, [t], t.inserted_at > ^at)
    end
  end

  defp cursor_time(user_id, cursor_id) do
    case Ecto.UUID.cast(cursor_id) do
      {:ok, uuid} ->
        repo().one(
          from(t in Token,
            where: t.id == ^uuid and t.sub == ^user_id,
            select: t.inserted_at
          )
        )

      :error ->
        nil
    end
  end
end
