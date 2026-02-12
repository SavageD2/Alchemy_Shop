# 🧙‍♂️ Formation NestJS - Alchimia SaaS - Récapitulatif

## 📚 Vue d'ensemble du projet

**Projet** : Alchimia SaaS - API de gestion de boutiques de potions  
**Stack technique** : NestJS + TypeORM + PostgreSQL + JWT + Passport  
**Objectif** : Construire une API REST professionnelle et production-ready

---

## ✅ Phase 1 : Architecture & Swagger

### Objectif
Créer la structure de base du projet NestJS, générer les modules principaux (`shops` et `potions`), configurer Swagger pour la documentation automatique, et activer les CORS.

### Commandes exécutées
```bash
npm install -g @nestjs/cli
nest new alchimia-saas
cd alchimia-saas
nest generate resource shops
nest generate resource potions
npm install @nestjs/swagger swagger-ui-express
```

### Configuration dans `main.ts`
```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Validation globale des DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // CORS
  app.enableCors({
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  });

  // Swagger
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
```

### Concepts clés
- **Architecture modulaire** : Chaque fonctionnalité vit dans son propre module
- **Swagger** : Documentation interactive auto-générée accessible sur `/api/docs`
- **CORS** : Permet les requêtes cross-origin depuis un frontend

---

## ✅ Phase 2 : Persistance avec TypeORM

### Objectif
Connecter l'application à PostgreSQL, créer les entités `Shop` et `Potion` avec leurs relations, et configurer TypeORM.

### Commandes exécutées
```bash
npm install @nestjs/typeorm typeorm pg
npm install @nestjs/config
```

### Fichier `.env`
```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=alchi_saas
DB_USER=postgres
DB_PASSWORD=savage
JWT_SECRET=b6ca33e628d2c956bf88f748ce3ee563636aeefcbd03e0625453cc3128bab499
JWT_EXPIRES_IN=3600s
```

### Configuration TypeORM dans `app.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('DB_HOST'),
        port: configService.get<number>('DB_PORT'),
        username: configService.get<string>('DB_USER'),
        password: configService.get<string>('DB_PASSWORD'),
        database: configService.get<string>('DB_NAME'),
        synchronize: true, // ⚠️ Uniquement en dev !
        autoLoadEntities: true,
      }),
    }),
    ShopsModule,
    PotionModule,
  ],
})
export class AppModule {}
```

### Entité Shop (`shops/shops.entity.ts`)
```typescript
import { Entity, Column, PrimaryGeneratedColumn, OneToMany } from 'typeorm';
import { Potion } from 'src/potion/potion.entity';

@Entity()
export class Shop {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  location: string;

  @OneToMany(() => Potion, (potion) => potion.shop)
  potions: Potion[];

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
```

### Entité Potion (`potion/potion.entity.ts`)
```typescript
import { Column, Entity, PrimaryGeneratedColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Shop } from 'src/shops/shops.entity';

@Entity()
export class Potion {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  effect: string;

  @Column()
  stock: number;

  @Column()
  price: number;

  @ManyToOne(() => Shop, (shop) => shop.potions)
  @JoinColumn({ name: 'shopId' })
  shop: Shop;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
```

### Enregistrement dans les modules
```typescript
// shops.module.ts
import { TypeOrmModule } from '@nestjs/typeorm';
import { Shop } from './shops.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Shop])],
  controllers: [ShopsController],
  providers: [ShopsService],
})
export class ShopsModule {}
```

### Injection des repositories
```typescript
// shops.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Shop } from './shops.entity';

@Injectable()
export class ShopsService {
  constructor(
    @InjectRepository(Shop)
    private shopRepository: Repository<Shop>,
  ) {}
}
```

### Concepts clés
- **ORM** : Manipuler la base de données avec des classes TypeScript
- **Entités** : Une classe = une table en base de données
- **Relations** : `@OneToMany` / `@ManyToOne` pour gérer les liens entre tables
- **Repository Pattern** : TypeORM fournit automatiquement les méthodes CRUD

---

## ✅ Phase 3 : Sécurité & Identité

### Objectif
Créer un système d'authentification avec JWT, hachage des mots de passe avec bcrypt, et protection des routes avec Passport.

### Commandes exécutées
```bash
npm install @nestjs/passport @nestjs/jwt passport passport-jwt bcrypt
npm install -D @types/passport-jwt @types/bcrypt
npm install class-validator class-transformer
nest generate resource users
nest generate module auth
nest generate service auth
nest generate controller auth
```

### Entité User (`users/entities/user.entity.ts`)
```typescript
import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn } from 'typeorm';

export enum UserRole {
  ALCHIMIST = 'alchimist',
  ADMIN = 'admin',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ select: false })
  password: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.ALCHIMIST,
  })
  role: UserRole;

  @CreateDateColumn()
  createdAt: Date;
}
```

### DTO avec validation (`users/dto/create-user.dto.ts`)
```typescript
import { IsEmail, IsEnum, IsOptional, IsString, MinLength } from 'class-validator';
import { UserRole } from '../entities/user.entity';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}
```

### Service Users (`users/users.service.ts`)
```typescript
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const newUser = this.userRepository.create({
      ...createUserDto,
      email: createUserDto.email.toLowerCase(),
      password: hashedPassword,
    });
    return this.userRepository.save(newUser);
  }

  findByEmail(email: string) {
    // Récupère le password même avec select: false
    return this.userRepository
      .createQueryBuilder('user')
      .where('user.email = :email', { email })
      .addSelect('user.password')
      .getOne();
  }
}
```

### Module Users (`users/users.module.ts`)
```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User } from './entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService], // ⚠️ Important pour AuthModule
})
export class UsersModule {}
```

### Service Auth (`auth/auth.service.ts`)
```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { AuthenticatedUser } from './interfaces/auth-user.interface';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<AuthenticatedUser | null> {
    const user = await this.usersService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      // ⚠️ Ne jamais retourner le password !
      const { password: _, ...result } = user;
      return result as AuthenticatedUser;
    }
    return null;
  }

  async login(user: AuthenticatedUser) {
    const payload = { email: user.email, sub: user.id, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
```

### Interfaces (`auth/interfaces/auth-user.interface.ts`)
```typescript
import { UserRole } from 'src/users/entities/user.entity';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
}

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
}
```

### Stratégie JWT (`auth/jwt.strategy.ts`)
```typescript
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthenticatedUser, JwtPayload } from './interfaces/auth-user.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  }
}
```

### Guard JWT (`auth/jwt-auth.guard.ts`)
```typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
```

### Controller Auth (`auth/auth.controller.ts`)
```typescript
import { Controller, Post, Body, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { UsersService } from 'src/users/users.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UsersService,
  ) {}

  @Post('register')
  register(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @Post('login')
  async login(@Body() createUserDto: CreateUserDto) {
    const user = await this.authService.validateUser(
      createUserDto.email,
      createUserDto.password,
    );
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return this.authService.login(user);
  }
}
```

### Module Auth (`auth/auth.module.ts`)
```typescript
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';

@Module({
  controllers: [AuthController],
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: configService.get('JWT_EXPIRES_IN') || '24h' },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}
```

### Concepts clés
- **Hachage** : Toujours hacher les mots de passe avec bcrypt (JAMAIS en clair)
- **JWT** : Token signé qui contient les infos utilisateur (stateless)
- **Passport** : Librarie d'authentification standard pour Node.js
- **Strategy** : Définit comment extraire et valider le token
- **Guard** : Protège les routes (à utiliser avec `@UseGuards(JwtAuthGuard)`)
- **Validation** : `class-validator` valide automatiquement les DTOs

---

## 🔴 Erreurs corrigées et explications

### Erreur 1 : Routes dupliquées
**Problème** : `@Post('auth/register')` au lieu de `@Post('register')`  
**Impact** : Route devient `/auth/auth/register`  
**Explication** : Les chemins s'additionnent en NestJS : `@Controller('auth')` + `@Post('register')` = `/auth/register`

### Erreur 2 : Mauvaise gestion des erreurs HTTP
**Problème** : Retourner `{ message: 'Invalid credentials' }` avec code 200  
**Impact** : Le client ne peut pas détecter l'erreur proprement  
**Explication** : Utiliser les exceptions NestJS (`UnauthorizedException`) pour retourner les bons codes HTTP

### Erreur 3 : JwtStrategy sans constructeur
**Problème** : Pas de `super()` dans le constructeur  
**Impact** : Passport ne sait pas comment extraire le token ni quel secret utiliser  
**Explication** : `PassportStrategy` a besoin de configuration via `super({ jwtFromRequest, secretOrKey })`

### Erreur 4 : JwtStrategy non enregistrée
**Problème** : Stratégie créée mais pas dans `providers[]`  
**Impact** : `JwtAuthGuard` ne fonctionne pas  
**Explication** : Pour être injectable, une classe doit être dans `providers` du module

### Erreur 5 : Entity User incomplète
**Problèmes multiples** :
- Pas d'enum pour les rôles → Valeurs non contraintes en BDD
- Pas de default → Risque d'oubli lors de la création
- Pas de `createdAt` → Impossible de tracer la création
- `select: false` sur `role` → Impossible d'utiliser le rôle pour les guards

**Explication** : Un enum TypeScript + TypeORM garantit l'intégrité des données

### Erreur 6 : findByEmail ne récupère pas le password
**Problème** : `select: false` exclut le champ des requêtes  
**Impact** : `bcrypt.compare()` ne peut pas valider le mot de passe  
**Solution** : Utiliser `QueryBuilder` avec `.addSelect('user.password')`

### Erreur 7 : validateUser expose le password
**Problème** : Retourner l'objet `user` complet avec le password  
**Impact** : Faille de sécurité potentielle  
**Solution** : Utiliser destructuring `const { password: _, ...result } = user` pour exclure le password

### Erreur 8 : DTO sans validation
**Problème** : Pas de décorateurs de validation  
**Impact** : N'importe quelle donnée peut être envoyée  
**Solution** : Utiliser `class-validator` (`@IsEmail`, `@MinLength`, etc.)

---

## 🧪 Tests de l'API

### 1. Créer un utilisateur
```http
POST http://localhost:3000/auth/register
Content-Type: application/json

{
  "email": "merlin@alchimia.com",
  "password": "potion123",
  "role": "alchimist"
}
```

**Réponse attendue :** Objet utilisateur avec `id`, `email`, `role`, `createdAt` (sans password)

### 2. Se connecter
```http
POST http://localhost:3000/auth/login
Content-Type: application/json

{
  "email": "merlin@alchimia.com",
  "password": "potion123"
}
```

**Réponse attendue :**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 3. Accéder à Swagger
Ouvrir : `http://localhost:3000/api/docs`

---

## 📁 Structure finale du projet

```
alchi-saas/
├── src/
│   ├── auth/
│   │   ├── dto/
│   │   ├── entities/
│   │   ├── interfaces/
│   │   │   └── auth-user.interface.ts
│   │   ├── auth.controller.ts
│   │   ├── auth.service.ts
│   │   ├── auth.module.ts
│   │   ├── jwt.strategy.ts
│   │   └── jwt-auth.guard.ts
│   ├── users/
│   │   ├── dto/
│   │   │   └── create-user.dto.ts
│   │   ├── entities/
│   │   │   └── user.entity.ts
│   │   ├── users.controller.ts
│   │   ├── users.service.ts
│   │   └── users.module.ts
│   ├── shops/
│   │   ├── shops.controller.ts
│   │   ├── shops.service.ts
│   │   ├── shops.module.ts
│   │   └── shops.entity.ts
│   ├── potion/
│   │   ├── potion.controller.ts
│   │   ├── potion.service.ts
│   │   ├── potion.module.ts
│   │   └── potion.entity.ts
│   ├── app.module.ts
│   └── main.ts
├── .env
├── package.json
└── tsconfig.json
```

---

## 🎯 Prochaines étapes (Phases à venir)

### Phase 4 : RBAC & Multi-tenancy
- Création d'un `RolesGuard` (rôles : ALCHIMIST, ADMIN)
- Décorateurs personnalisés (`@Roles()`, `@CurrentUser()`)
- Isolation des données par boutique

### Phase 5 : Validation & DTOs avancés
- DTOs pour toutes les entités
- Utilisation poussée de `class-transformer`

### Phase 6 : Background Tasks
- Implémentation de `@nestjs/schedule`
- Cron job pour vérification automatique des stocks

### Phase 7 : Finition Pro
- `TransformInterceptor` pour uniformiser les réponses
- `ClassSerializerInterceptor` pour masquer les données sensibles
- Logging et monitoring

---

## 💡 Concepts NestJS appris

| Concept | Description |
|---------|-------------|
| **Modules** | Organisent l'application en blocs fonctionnels |
| **Controllers** | Gèrent les routes HTTP et retournent des réponses |
| **Services** | Contiennent la logique métier (injectable) |
| **Providers** | Classes injectables via Dependency Injection |
| **Guards** | Protègent les routes (authentification, autorisation) |
| **Pipes** | Transforment/valident les données entrantes |
| **DTOs** | Définissent la structure des données échangées |
| **Entities** | Représentent les tables de base de données |
| **Repositories** | Abstraction pour accéder aux données |
| **Strategies** | Définissent les méthodes d'authentification |

---

## 📦 Packages installés

```json
{
  "dependencies": {
    "@nestjs/common": "^10.x",
    "@nestjs/config": "^3.x",
    "@nestjs/core": "^10.x",
    "@nestjs/jwt": "^10.x",
    "@nestjs/passport": "^10.x",
    "@nestjs/platform-express": "^10.x",
    "@nestjs/swagger": "^7.x",
    "@nestjs/typeorm": "^10.x",
    "bcrypt": "^5.x",
    "class-transformer": "^0.5.x",
    "class-validator": "^0.14.x",
    "passport": "^0.7.x",
    "passport-jwt": "^4.x",
    "pg": "^8.x",
    "swagger-ui-express": "^5.x",
    "typeorm": "^0.3.x"
  },
  "devDependencies": {
    "@types/bcrypt": "^5.x",
    "@types/passport-jwt": "^4.x"
  }
}
```

---

## 🔐 Bonnes pratiques appliquées

✅ **Sécurité** : Mots de passe hachés, JWT signés, validation des entrées  
✅ **Architecture** : Séparation des responsabilités (modules, services, controllers)  
✅ **Configuration** : Variables d'environnement via `.env`  
✅ **Documentation** : Swagger auto-généré  
✅ **Validation** : DTOs avec class-validator  
✅ **Types** : TypeScript strict pour éviter les erreurs  
✅ **Base de données** : Relations TypeORM bien définies  
✅ **HTTP** : Codes de statut et exceptions appropriés

---

**🎓 Fin du récapitulatif - Phases 1 à 3 complétées !**
