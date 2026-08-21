export const CHARACTER_SETS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}:,.?",
};

export const AMBIGUOUS_CHARACTERS = new Set("Il1O0o");

export const MIN_PASSWORD_LENGTH = 6;
export const MAX_PASSWORD_LENGTH = 64;
export const DEFAULT_PASSWORD_LENGTH = 12;
export const MIN_PASSPHRASE_WORDS = 3;
export const MAX_PASSPHRASE_WORDS = 12;
export const DEFAULT_PASSPHRASE_WORDS = 5;

export const PASSPHRASE_WORDS = [
  "anchor", "apricot", "archive", "arrow", "autumn", "badge", "bamboo", "beacon",
  "berry", "blanket", "blossom", "blueprint", "breeze", "cabin", "cactus", "camera",
  "canyon", "captain", "caravan", "castle", "cedar", "cello", "circle", "citadel",
  "clover", "comet", "compass", "coral", "cricket", "crystal", "daisy", "dawn",
  "desert", "dolphin", "dragon", "drift", "eagle", "ember", "falcon", "feather",
  "fern", "festival", "flame", "forest", "galaxy", "garden", "glacier", "harbor",
  "hazel", "helmet", "horizon", "island", "jacket", "jasmine", "journey", "lantern",
  "lemon", "library", "lotus", "magnet", "marble", "meadow", "meteor", "midnight",
  "mint", "monsoon", "mountain", "nectar", "night", "oasis", "ocean", "olive",
  "orchard", "otter", "pebble", "pepper", "piano", "picnic", "planet", "plaza",
  "pocket", "prairie", "quartz", "rainbow", "raven", "reef", "ribbon", "rocket",
  "saffron", "sailor", "salmon", "scarlet", "shadow", "shelter", "silver", "spectrum",
  "spice", "spiral", "spring", "square", "starling", "stone", "summer", "sunrise",
  "tangle", "thunder", "timber", "topaz", "trail", "tulip", "valley", "velvet",
  "violet", "volcano", "walnut", "waterfall", "willow", "winter", "wonder", "zephyr",
];