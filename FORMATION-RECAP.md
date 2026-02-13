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

## ✅ Phase 4 : RBAC & Multi-tenancy

### Objectif
Implémenter un contrôle d'accès basé sur les rôles (RBAC), créer des décorateurs personnalisés pour gérer les permissions, et mettre en place le multi-tenancy pour que chaque boutique accède uniquement à ses propres données.

### Concepts clés

**RBAC (Role-Based Access Control)**  
Système qui contrôle l'accès aux ressources selon le rôle de l'utilisateur. Un ALCHIMIST gère sa boutique, un ADMIN a tous les droits.

**Décorateurs personnalisés**  
Permettent d'ajouter des métadonnées aux routes et d'extraire des données de la requête de manière réutilisable.

**Multi-tenancy**  
Architecture où chaque client (tenant = boutique) est isolé. Un utilisateur ne voit que les données de sa boutique.

### Modifications des entités

#### Entité User avec shopId (`users/entities/user.entity.ts`)
```typescript
import { Shop } from 'src/shops/shops.entity';
import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';

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

  @ManyToOne(() => Shop, (shop) => shop.users, { nullable: true })
  @JoinColumn({ name: 'shopId' })
  shop: Shop;

  @Column({ nullable: true })
  shopId: string; // ⚠️ Clé étrangère explicite pour le multi-tenancy

  @CreateDateColumn()
  createdAt: Date;
}
```

#### Entité Potion avec shopId (`potion/potion.entity.ts`)
```typescript
import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Shop } from 'src/shops/shops.entity';

@Entity()
export class Potion {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column()
  effect: string;

  @Column()
  stock: number;

  @Column('decimal', { precision: 10, scale: 2 })
  price: number;

  @ManyToOne(() => Shop, (shop) => shop.potions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'shopId' })
  shop: Shop;

  @Column()
  shopId: string; // ⚠️ Permet le filtrage direct

  @CreateDateColumn()
  createdAt: Date;
}
```

### Décorateurs personnalisés

#### @Roles() - Décorateur de rôles (`auth/decorators/roles.decorator.ts`)
```typescript
import { SetMetadata } from '@nestjs/common';
import { UserRole } from 'src/users/entities/user.entity';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
```

**Utilisation :**
```typescript
@Roles(UserRole.ADMIN)
@Get()
findAll() { ... }
```

#### @CurrentUser() - Extraction de l'utilisateur (`auth/decorators/current-user.decorator.ts`)
```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthenticatedUser } from '../interfaces/auth-user.interface';

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): AuthenticatedUser => {
    const request = ctx.switchToHttp().getRequest<{ user: AuthenticatedUser }>();
    return request.user;
  },
);
```

**Utilisation :**
```typescript
@Get('my-potions')
getMyPotions(@CurrentUser() user: AuthenticatedUser) {
  return this.potionsService.findByShop(user.shopId);
}
```

### Guards

#### RolesGuard - Vérification des rôles (`auth/guards/auth.guards.ts`)
```typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { UserRole } from 'src/users/entities/user.entity';
import { AuthenticatedUser } from '../interfaces/auth-user.interface';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true; // Pas de restriction de rôle
    }

    const request = context.switchToHttp().getRequest<{ user: AuthenticatedUser }>();
    const user = request.user;

    return requiredRoles.some((role) => user.role === role);
  }
}
```

**Comment ça marche :**
1. `Reflector` lit les métadonnées attachées par `@Roles()`
2. Si aucun rôle requis → accès autorisé
3. Sinon, vérifie que le rôle de l'utilisateur correspond

### Interfaces mises à jour

#### AuthenticatedUser avec shopId (`auth/interfaces/auth-user.interface.ts`)
```typescript
import { UserRole } from 'src/users/entities/user.entity';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  shopId?: string; // ⚠️ Essentiel pour le multi-tenancy
}

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  shopId?: string; // ⚠️ Transmis via le JWT
}
```

### Service Auth - JWT avec shopId

```typescript
async login(user: AuthenticatedUser) {
  const payload = {
    email: user.email,
    sub: user.id,
    role: user.role,
    shopId: user.shopId, // ⚠️ Inclus dans le token
  };
  return {
    access_token: this.jwtService.sign(payload),
  };
}
```

### JwtStrategy - Extraction du shopId

```typescript
async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
  return {
    id: payload.sub,
    email: payload.email,
    role: payload.role,
    shopId: payload.shopId, // ⚠️ Récupéré du JWT
  };
}
```

### Controllers protégés

#### Shops Controller (`shops/shops.controller.ts`)
```typescript
import { Controller, Get, Post, UseGuards, Body } from '@nestjs/common';
import { ShopsService } from './shops.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/auth.guards';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { UserRole } from 'src/users/entities/user.entity';
import type { AuthenticatedUser } from 'src/auth/interfaces/auth-user.interface';

@Controller('shops')
@UseGuards(JwtAuthGuard, RolesGuard) // ⚠️ Ordre important : JWT d'abord !
export class ShopsController {
  constructor(private readonly shopsService: ShopsService) {}

  @Post()
  @Roles(UserRole.ADMIN) // Seuls les admins créent des boutiques
  create(@Body() createShopDto: { name: string; location: string }) {
    return this.shopsService.createShop(createShopDto);
  }

  @Get()
  @Roles(UserRole.ADMIN) // Seuls les admins voient toutes les boutiques
  findAll() {
    return this.shopsService.findAll();
  }

  @Get('my-shop')
  getMyShop(@CurrentUser() user: AuthenticatedUser) {
    if (!user.shopId) {
      return { message: 'No shop assigned to this user' };
    }
    return this.shopsService.findOne(user.shopId);
  }
}
```

#### Potions Controller avec Multi-tenancy (`potion/potion.controller.ts`)
```typescript
import { Controller, Post, Get, UseGuards, Body, ForbiddenException } from '@nestjs/common';
import { PotionService } from './potion.service';
import { CreatePotionDto } from './dto/create-potion.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from 'src/auth/interfaces/auth-user.interface';

@Controller('potions')
@UseGuards(JwtAuthGuard) // Toutes les routes nécessitent une authentification
export class PotionController {
  constructor(private readonly potionService: PotionService) {}

  @Post()
  async createPotion(
    @Body() createPotionDto: CreatePotionDto,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    if (!user.shopId) {
      throw new ForbiddenException('You must be assigned to a shop to create potions');
    }
    return this.potionService.createPotionForShop(createPotionDto, user.shopId);
  }

  @Get()
  async getMyPotions(@CurrentUser() user: AuthenticatedUser) {
    if (!user.shopId) {
      return [];
    }
    return this.potionService.findByShop(user.shopId); // ⚠️ Filtrage automatique
  }
}
```

### Services avec Multi-tenancy

#### Potion Service (`potion/potion.service.ts`)
```typescript
import { Injectable } from '@nestjs/common';
import { Potion } from './potion.entity';
import { CreatePotionDto } from './dto/create-potion.dto';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class PotionService {
  constructor(
    @InjectRepository(Potion)
    private potionRepository: Repository<Potion>,
  ) {}

  async createPotionForShop(dto: CreatePotionDto, shopId: string): Promise<Potion> {
    const potion = this.potionRepository.create({
      ...dto,
      shopId, // ⚠️ Lie automatiquement à la boutique
    });
    return this.potionRepository.save(potion);
  }

  async findByShop(shopId: string): Promise<Potion[]> {
    return this.potionRepository.find({
      where: { shopId }, // ⚠️ Filtrage multi-tenant
      order: { createdAt: 'DESC' },
    });
  }

  async findAll(): Promise<Potion[]> {
    // Pour les admins uniquement
    return this.potionRepository.find({
      relations: ['shop'],
      order: { createdAt: 'DESC' },
    });
  }
}
```

### DTO avec validation du shopId

```typescript
import { IsEmail, IsEnum, IsOptional, IsString, IsUUID, MinLength } from 'class-validator';
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

  @IsOptional()
  @IsUUID() // ⚠️ Valide le format UUID
  shopId?: string;
}
```

---

## 🔴 Erreurs Phase 4 - Corrigées avec explications

### Erreur 1 : Colonne shopId manquante
**Problème** : Relation sans colonne FK explicite  
**Impact** : Impossible de filtrer directement avec `where: { shopId }`  
**Correction** : Ajout de `@Column() shopId: string;` dans User et Potion

### Erreur 2 : JWT sans shopId
**Problème** : Le payload ne contenait pas shopId  
**Impact** : Impossible de récupérer la boutique de l'utilisateur  
**Correction** : Ajout de `shopId` dans le payload et les interfaces

### Erreur 3 : Décorateurs mal typés
**Problème** : `Roles(...roles: string[])` au lieu de `UserRole[]`  
**Impact** : Pas de typage fort  
**Correction** : Utilisation de l'enum `UserRole`

### Erreur 4 : Nom du décorateur non conventionnel
**Problème** : `currentUser` au lieu de `CurrentUser`  
**Impact** : Non-respect des conventions  
**Correction** : Renommage en PascalCase

### Erreur 5 : Guards mal ordonnés
**Problème** : `@Roles()` avant `@UseGuards()`  
**Impact** : RolesGuard pas appliqué  
**Correction** : Ordre correct : métadonnées puis guards

### Erreur 6 : Routes dupliquées
**Problème** : Deux `@Post()` dans le même controller  
**Impact** : Conflit de routes  
**Correction** : Suppression des doublons

### Erreur 7 : Pas de filtrage multi-tenant
**Problème** : `findAll()` retournait toutes les potions  
**Impact** : Faille de sécurité  
**Correction** : Ajout de `findByShop(shopId)`

### Erreur 8 : Validation manquante
**Problème** : shopId sans validation  
**Impact** : Valeurs invalides acceptées  
**Correction** : Ajout de `@IsUUID()`

### Erreur 9 : JwtStrategy incomplet
**Problème** : Ne retournait pas shopId  
**Impact** : `@CurrentUser()` sans shopId  
**Correction** : Ajout dans le `validate()`

### Erreur 10 : Relation non nullable
**Problème** : User doit avoir un shop obligatoirement  
**Impact** : Impossible de créer un admin sans shop  
**Correction** : `{ nullable: true }` sur la relation

---

## 🧪 Tests Multi-tenancy

### Scénario de test

1. **Créer une boutique (Admin)**
```http
POST /shops
Authorization: Bearer <admin_token>

{
  "name": "Potion Palace",
  "location": "Diagon Alley"
}
```

2. **Créer un utilisateur lié à la boutique**
```http
POST /auth/register

{
  "email": "merlin@alchimia.com",
  "password": "potion123",
  "role": "alchimist",
  "shopId": "uuid-de-la-boutique"
}
```

3. **Créer une potion**
```http
POST /potions
Authorization: Bearer <merlin_token>

{
  "name": "Felix Felicis",
  "effect": "Chance",
  "stock": 10,
  "price": 150.00
}
```

4. **Récupérer ses potions**
```http
GET /potions
Authorization: Bearer <merlin_token>
```
→ Ne voit que les potions de sa boutique !

5. **Vérifier l'isolation**
- Créer un autre utilisateur dans une autre boutique
- Vérifier qu'il ne voit pas les potions de Merlin

---

## 💡 Concepts avancés appris

| Concept | Description |
|---------|-------------|
| **RBAC** | Contrôle d'accès basé sur les rôles |
| **Multi-tenancy** | Isolation des données par client |
| **Custom Decorators** | Décorateurs réutilisables pour métadonnées |
| **Param Decorators** | Extraction de données de la requête |
| **Guards** | Logique de protection des routes |
| **Reflector** | Lecture des métadonnées NestJS |
| **Metadata** | Données attachées aux routes/classes |
| **Foreign Keys** | Clés étrangères explicites pour filtrage |

---

## 📦 Structure complète après Phase 4

```
src/auth/
├── decorators/
│   ├── roles.decorator.ts        ← @Roles(UserRole.ADMIN)
│   └── current-user.decorator.ts ← @CurrentUser()
├── guards/
│   ├── jwt-auth.guard.ts
│   └── auth.guards.ts            ← RolesGuard (vérifie les rôles)
```

---

**🎓 Phase 4 terminée ! Le système RBAC et Multi-tenancy est opérationnel.**

---

## 🎯 Prochaines étapes

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
