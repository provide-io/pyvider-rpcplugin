/**
 * ASCII art data and utility functions
 */

// The original ASCII art pattern
export const asciiArt = `
                                                          ::
                                                        *:@@:%
                                                        ::  ::
               :::-=-:::::                              : ::
           :::%@:@%:::::::=:                            ::  ::
          ==::::::::::::=#=:=                          :*:  ::::  :#*.  ##:::##:#:=*:::=:::::::.
           @@@@@@@@@@@@@@@=:==                      ::  . :: :  ::    : :  : :  :  : : :::: :: :
                        @#=-=@                        ::::  ::::  :::: ::::::::::::::::::::::::
                        **===@                         ::.  ::                       :#:=:
                       =@*=*@:                         :  :: :
                     :+@@@@@@                          :::  ::
                    :%@@@@@=                           ::::::::
                   :@@@@@@:                            : :   ::
                 ::@@@@@@                    ==        :     ::                       :::
                :=@@@@@@          :====-      :=:      ::. .:::                       :@:
               :*@@@@@=        .:::::::::=     :=:     :::  :::                        ::
          ::-===@@@@@=       ::::::::::@@%      :=:    :  ::  :                        *
         %::::::::=@@.    .::::::::=@@@@*=*=.   ==@    ::    ::                       @:@
         @@:::::::::::::::::::::-@@@@==::::==*  ==@    :::  :::
       :::*@@@=-:::::::::::::=*@@@*=::::::::=* :*@=    :  ::  :            ########@@######@@######
      :::::::@@@@@@*=====+%@@@@+=::::::::=%@@@@@@@     : :  : :            ######@@##########%@####
      *:::::::::=*@@@@@@@@#=:::::::::::+@@@@@@@@@     .#:::::::
       @@*:::::::::::::::::::::::::::*@@@@@@@@@@      ::.:  . :
         =@@@@@*::::::::::::::-*@@@@@@@@@@@@@.        ::  ::  :
                  :#@@@@@@@@@=.                       :::    ::
`;

/**
 * Parses the ASCII art into a 2D array for easier processing
 * @returns {Array<Array<string>>} A 2D array of characters
 */
export function parseAsciiArt() {
  return asciiArt
    .split('\n')
    .filter(line => line.length > 0) // Remove empty lines
    .map(line => [...line]);
}

/**
 * Gets the dimensions of the ASCII grid
 * @param {Array<Array<string>>} grid - The parsed ASCII grid
 * @returns {Object} Width and height of the grid
 */
export function getGridDimensions(grid) {
  return {
    width: Math.max(...grid.map(row => row.length)),
    height: grid.length
  };
}

/**
 * Get character groups (categorizes characters for different visual effects)
 * @returns {Object} Groups of characters by type
 */
export function getCharacterGroups() {
  return {
    box: ['@', '#', '%'],
    star: ['*', '+'],
    line: ['-', '='],
    dot: ['.', ':'],
    other: ['\\', '/', '|', '_']
  };
}
