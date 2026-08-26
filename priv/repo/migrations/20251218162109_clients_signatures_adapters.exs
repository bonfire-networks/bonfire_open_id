defmodule Bonfire.Common.Repo.Migrations.ClientsSignaturesAdapters do
  use Ecto.Migration

  use Boruta.Migrations.ClientsSignaturesAdapters

  # the macro's `change/0` does `modify :did, :text` with no `from:`, which Ecto can't invert. We don't need to reverse boruta's schema, just to not block rolling back ours
  def down, do: nil
end
