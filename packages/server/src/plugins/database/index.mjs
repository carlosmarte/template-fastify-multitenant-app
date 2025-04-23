import { Sequelize, DataTypes } from "sequelize";

export const requestPlugin = async (fastify, options) => {
  const sequelize = new Sequelize("mydatabase", "myuser", "mypassword", {
    host: "localhost",
    dialect: "postgres",
  });

  try {
    await sequelize.authenticate();
    console.log("Connection has been established successfully.");
  } catch (error) {
    console.error("Unable to connect to the database:", error);
  }

  fastify.addHook("onClose", async (instance) => {
    await sequelize.close();
  });

  fastify.decorate("db", sequelize);

  sequelize.define(
    "Users",
    {
      name: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      permission_type: DataTypes.STRING,
      rule_v0: DataTypes.STRING,
      rule_v1: DataTypes.STRING,
      rule_v2: DataTypes.STRING,
      rule_v3: DataTypes.STRING,
      rule_v4: DataTypes.STRING,
      rule_v5: DataTypes.STRING,
      rule_v6: DataTypes.STRING,
      rule_v7: DataTypes.STRING,
      policy_definition_id: DataTypes.BIGINT,
    },
    {
      tableName: "users",
      timestamps: true,
      createdAt: "createdAt",
      updatedAt: "updatedAt",
      schema: "public",
    }
  );

  sequelize.models.Users.sync({ force: true });
};

export default requestPlugin;
