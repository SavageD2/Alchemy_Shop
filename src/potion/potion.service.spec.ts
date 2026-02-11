import { Test, TestingModule } from '@nestjs/testing';
import { PotionService } from './potion.service';

describe('PotionService', () => {
  let service: PotionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PotionService],
    }).compile();

    service = module.get<PotionService>(PotionService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
