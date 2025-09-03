import { NestFactory } from '@nestjs/core';
import { ClassSerializerInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Configura interceptor global para serialização automática
  // Remove campos marcados com @Exclude() de todas as respostas HTTP
  app.useGlobalInterceptors(
    new ClassSerializerInterceptor(app.get(Reflector))
  );
  
  await app.listen(3000);
  console.log('Server running on http://localhost:3000');
}

bootstrap();