import { ConsoleLogger, FileLogger, Logger } from "./logger";

export const VERSION: string = "0.0.1"

export const IS_PRODUCTION: boolean = process.env.PRODUCTION != undefined;

export const LOGGER: Logger = IS_PRODUCTION ? new FileLogger(process.env.LOG_FILE ?? "./backend.log") : new ConsoleLogger();