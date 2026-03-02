const { PostgresStorage } = require("./postgres");
const { SqliteStorage } = require("./sqlite");

function createStorage(config) {
  if (config.databaseUrl) {
    return new PostgresStorage(config.databaseUrl);
  }

  return new SqliteStorage(config.sqlitePath);
}

module.exports = {
  createStorage
};
