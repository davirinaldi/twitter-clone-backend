import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { UsersModule } from './modules/users/users.module'; 

@Module({
  imports: [ConfigModule.forRoot({
    isGlobal: true,
  }), 
    TypeOrmModule.forRoot({
    type: 'postgres',
    host: process.env.DATABASE_HOST || 'localhost',
    port: Number(process.env.DATABASE_PORT) || 5432,
    username: process.env.DATABASE_USER || 'postgres',
    password: process.env.DATABASE_PASSWORD || 'postgres',
    database: process.env.DATABASE_NAME || 'twitter_clone',
    entities: [__dirname + '/**/*.entity{.ts,.js}'],
    synchronize: true,
    logging: false, // Desabilitar logging SQL
    retryAttempts: 5,
    retryDelay: 3000,
  }),
  UsersModule,
  ],
  
  
})
export class AppModule {}
