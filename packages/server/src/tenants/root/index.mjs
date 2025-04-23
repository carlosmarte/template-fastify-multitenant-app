
export const NAME = "root";


export default async function initialize(app, options) {
  app.log.info(`Initializing tenant: ${NAME}`);

  return {
    initialized: new Date().toISOString(),
  };
}
