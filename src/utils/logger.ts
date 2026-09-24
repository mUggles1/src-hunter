import winston from 'winston';
import { resolve } from 'path';

// 日志级别
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

// 日志颜色
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  debug: 'blue',
};

winston.addColors(colors);

// 日志格式
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// 控制台格式（带颜色）
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let metaStr = '';
    if (Object.keys(meta).length > 0) {
      metaStr = JSON.stringify(meta, null, 2);
    }
    return `${timestamp} [${level}]: ${message} ${metaStr}`;
  })
);

// 创建日志目录
const logDir = resolve(process.cwd(), 'logs');

// 创建 logger
export const logger = winston.createLogger({
  levels,
  level: process.env.LOG_LEVEL || 'info',
  format,
  transports: [
    // 错误日志
    new winston.transports.File({
      filename: resolve(logDir, 'error.log'),
      level: 'error',
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 5,
    }),
    // 所有日志
    new winston.transports.File({
      filename: resolve(logDir, 'combined.log'),
      maxsize: 50 * 1024 * 1024, // 50MB
      maxFiles: 10,
    }),
    // 控制台输出到 stderr（避免干扰 MCP 协议的 stdout 通道）
    new winston.transports.Console({
      format: consoleFormat,
      stderrLevels: ['error', 'warn', 'info', 'debug'],
    }),
  ],
  exceptionHandlers: [
    new winston.transports.File({
      filename: resolve(logDir, 'exceptions.log'),
    }),
  ],
  rejectionHandlers: [
    new winston.transports.File({
      filename: resolve(logDir, 'rejections.log'),
    }),
  ],
});

// 在开发环境下显示调试日志
if (process.env.NODE_ENV === 'development') {
  logger.level = 'debug';
}

export default logger;
