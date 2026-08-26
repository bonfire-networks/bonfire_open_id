defmodule Bonfire.Common.Repo.Migrations.ClientsKeyPairTypes do
  use Ecto.Migration

  use Boruta.Migrations.ClientsKeyPairTypes

  # the macro's `change/0` runs an `execute "UPDATE oauth_clients …"`, which Ecto can't invert. We don't need to reverse boruta's schema, just to not block rolling back ours
  def down, do: nil
end
