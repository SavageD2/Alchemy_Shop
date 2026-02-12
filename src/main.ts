import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Activer la validation automatique des DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Enlève les propriétés non définies dans le DTO
      forbidNonWhitelisted: true, // Rejette les requêtes avec propriétés inconnues
      transform: true, // Transforme automatiquement les types
    }),
  );

  // Activer les CORS
  app.enableCors({
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  });

  // Configuration Swagger
  const config = new DocumentBuilder()
    .setTitle('Alchimia SaaS API')
    .setDescription('Gestion de stock et potions pour les alchimistes')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(process.env.PORT ?? 3000);
}

bootstrap();
